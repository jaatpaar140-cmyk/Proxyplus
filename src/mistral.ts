import { Provider, ProviderModel } from "./types";
import { ProviderAdapter, fetchMediaAsBase64, parseContentBlock, ensureImagesInMessages, NormalizedFunctionTool, normalizeFunctionTool } from "./providers";

export class MistralAdapter implements ProviderAdapter {
  async fetchChatCompletion(provider: Provider, model: ProviderModel, body: any, customCfOpts?: any, signal?: AbortSignal | null): Promise<Response> {
    const cleanBody = { ...body };
    delete cleanBody.conversation_id;
    delete cleanBody.virtualKey;
    delete cleanBody.appName;
    delete cleanBody.allowedModels;
    delete cleanBody.allowedProviders;
    delete cleanBody.smartPlus;
    delete cleanBody.multimodalRestrict;

    const messagesWithImages = ensureImagesInMessages(cleanBody);
    delete cleanBody.images;
    delete cleanBody.image;

    // Format messages for Mistral
    const formattedMessages = await Promise.all(messagesWithImages.map(async (msg: any) => {
      // Mistral expects assistant messages with tool_calls to have either a string content or omitted, but NOT explicit null?
      // Actually, Mistral often drops the tool call or throws an error if it sees an empty string or null. Omit it entirely.
      if (msg.role === "assistant" && msg.tool_calls) {
         if (msg.content === null || msg.content === "") {
             delete msg.content;
         }
      }

      // If it's a tool message, Mistral STRICTLY does not want `name` parameter in it.
      if (msg.role === "tool") {
          const newMsg = { ...msg };
          delete newMsg.name;
          return newMsg;
      }

      // Handle images for multimodal models (like pixtral)
      const rawMsgImage = msg.image_url || msg.image || (Array.isArray(msg.images) ? msg.images[0] : null);
      if (rawMsgImage && typeof msg.content === "string") {
        const parsed = parseContentBlock({ type: "image_url", image_url: rawMsgImage });
        let imgUrl = parsed.url || "";
        if (parsed.base64Data) {
          imgUrl = `data:${parsed.mimeType || "image/jpeg"};base64,${parsed.base64Data}`;
        } else if (imgUrl && imgUrl.startsWith("http")) {
          const fetched = await fetchMediaAsBase64(imgUrl);
          if (fetched) imgUrl = `data:${fetched.mimeType};base64,${fetched.base64Data}`;
        }
        return {
          ...msg,
          content: [
            { type: "text", text: msg.content },
            { type: "image_url", image_url: { url: imgUrl } }
          ]
        };
      }

      if (!Array.isArray(msg.content)) return msg;

      let hasMedia = false;
      const mediaBlocks: any[] = [];

      for (const c of msg.content) {
        const parsed = parseContentBlock(c);
        if (parsed.type === "media") {
          hasMedia = true;
          let imgUrl = parsed.url || "";
          if (parsed.base64Data) {
            imgUrl = `data:${parsed.mimeType || "image/jpeg"};base64,${parsed.base64Data}`;
          } else if (imgUrl && imgUrl.startsWith("http")) {
            const fetched = await fetchMediaAsBase64(imgUrl);
            if (fetched) imgUrl = `data:${fetched.mimeType};base64,${fetched.base64Data}`;
          }
          if (imgUrl) {
            mediaBlocks.push({ type: "image_url", image_url: { url: imgUrl } });
          }
        } else {
          if (parsed.text) {
            mediaBlocks.push({ type: "text", text: parsed.text });
          }
        }
      }

      if (!hasMedia) {
        let combinedText = "";
        for (const b of mediaBlocks) {
          if (b.type === "text") combinedText += (combinedText ? "\n" : "") + b.text;
        }
        return { ...msg, content: combinedText || (typeof msg.content === "string" ? msg.content : "") };
      }

      return { ...msg, content: mediaBlocks };
    }));

    // Normalize tools
    if (Array.isArray(cleanBody.tools) && cleanBody.tools.length > 0) {
      cleanBody.tools = cleanBody.tools
        .map(normalizeFunctionTool)
        .filter((f: NormalizedFunctionTool | null): f is NormalizedFunctionTool => f !== null)
        .map((f: NormalizedFunctionTool) => ({
          type: "function",
          function: f
        }));
    }

    const outboundBody = {
      ...cleanBody,
      messages: formattedMessages,
      model: model.modelId
    };

    const authHeader = provider.authHeaderFormat ? provider.authHeaderFormat.replace("{key}", provider.apiKey) : `Bearer ${provider.apiKey}`;
    const headers = new Headers();
    headers.set("Authorization", authHeader);
    headers.set("Content-Type", "application/json");
    headers.set("Accept-Encoding", "identity");

    const requestInit: RequestInit<any> = {
      method: "POST",
      headers,
      body: JSON.stringify(outboundBody),
      cf: customCfOpts || { cacheTtl: 0, cacheEverything: false }
    };
    if (signal) requestInit.signal = signal;

    let base = provider.baseUrl.trim().replace(/\/+$/, '');
    let url: string;
    if (base.endsWith('/chat/completions')) url = base;
    else if (base.endsWith('/v1')) url = `${base}/chat/completions`;
    else url = `${base}/v1/chat/completions`;

    // Mistral stream/non-stream response normalization is handled robustly
    // by GatewayRouter's built-in `proxySSE` (which uses `pipeHardenedSSE`) 
    // and its standard JSON parser.
    return fetch(url, requestInit);
  }
}
