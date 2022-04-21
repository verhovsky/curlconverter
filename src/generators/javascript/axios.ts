import * as util from "../../util.js";
import type { Request, Warnings } from "../../util.js";

import jsesc from "jsesc";

const supportedArgs = new Set([
  "url",
  "request",
  "user-agent",
  "cookie",
  "data",
  "data-raw",
  "data-ascii",
  "data-binary",
  "data-urlencode",
  "json",
  "form",
  "form-string",
  "referer",
  "get",
  "header",
  "head",
  "no-head",
  "user",
  "proxy",
  "proxy-user",
  "max-time",
]);

const repr = (value: string | object, indentLevel?: number): string => {
  const escaped = jsesc(value, {
    quotes: "single",
    minimal: false,
    compact: false,
    indent: "    ",
    indentLevel: indentLevel ? indentLevel : 0,
  });
  if (typeof value === "string") {
    return "'" + escaped + "'";
  }
  return escaped;
};

// TODO: @
const getDataString = (request: Request): [string | null, string | null] => {
  if (!request.data) {
    return [null, null];
  }

  const originalStringRepr = repr(request.data);

  const contentType = util.getContentType(request);
  if (contentType === "application/json") {
    const parsed = JSON.parse(request.data);
    const backToString = JSON.stringify(parsed);
    const jsonAsJavaScriptString = repr(parsed, 1);

    const result = "JSON.stringify(" + jsonAsJavaScriptString + ")";
    return [result, request.data !== backToString ? originalStringRepr : null];
  }
  if (contentType === "application/x-www-form-urlencoded") {
    const query = util.parseQueryString(request.data);
    const queryDict = query[1];
    if (
      queryDict &&
      Object.values(queryDict).every((v) => typeof v === "string")
    ) {
      // check for exact match
      if (
        util.getHeader(request, "content-type") ===
        "application/x-www-form-urlencoded"
      ) {
        util.deleteHeader(request, "content-type");
      }
      return [repr(queryDict, 1), null];
    } else {
      return [originalStringRepr, null];
    }
  }
  return [null, null];
};

const buildConfigObject = (
  request: Request,
  method: string,
  methods: string[],
  dataMethods: string[],
  hasSearchParams: boolean
): string => {
  let code = "{\n";

  if (!methods.includes(method)) {
    // Axios probably uppercases methods
    code += "    method: " + repr(method) + ",\n";
  }
  if (hasSearchParams) {
    // code += "    params,\n";
    code += "    params: params,\n";
  } else if (request.queryDict) {
    code += "    params: " + repr(request.queryDict, 1) + ",\n";
  }

  if ((request.headers && request.headers.length) || request.multipartUploads) {
    code += "    headers: {\n";
    if (request.multipartUploads) {
      code += "        ...form.getHeaders(),\n";
    }
    for (const [key, value] of request.headers || []) {
      code += "        " + repr(key) + ": " + repr(value || "") + ",\n";
    }
    if (code.endsWith(",\n")) {
      code = code.slice(0, -2);
      code += "\n";
    }
    code += "    },\n";
  }

  if (request.auth) {
    const [username, password] = request.auth;
    code += "    auth: {\n";
    code += "        username: " + repr(username);
    if (password) {
      code += ",\n";
      code += "        password: " + repr(password) + "\n";
    } else {
      code += "\n";
    }
    code += "    },\n";
  }

  if (!dataMethods.includes(method)) {
    if (request.data) {
      let dataString, commentedOutDataString;
      try {
        [dataString, commentedOutDataString] = getDataString(request);
        if (!dataString) {
          dataString = repr(request.data);
        }
      } catch {
        dataString = repr(request.data);
      }
      if (commentedOutDataString) {
        code += "    // data: " + commentedOutDataString + ",\n";
      }
      code += "    data: " + dataString + ",\n";
    } else if (request.multipartUploads) {
      // TODO: warn if method dosen't send data
      code += "    data: form,\n";
    }
  }

  if (request.timeout) {
    const timeout = parseFloat(request.timeout);
    if (!isNaN(timeout) && timeout > 0) {
      code += "    timeout: " + timeout * 1000 + ",\n";
    }
  }

  if (request.proxy === "") {
    // TODO: this probably won't be set if it's empty
    // TODO: could have --socks5 proxy
    code += "    proxy: false,\n";
  } else if (request.proxy) {
    // TODO: do this parsing in utils.ts
    const proxy = request.proxy.includes("://")
      ? request.proxy
      : "http://" + request.proxy;
    let [protocol, host] = proxy.split(/:\/\/(.*)/s, 2);
    protocol =
      protocol.toLowerCase() === "socks" ? "socks4" : protocol.toLowerCase();
    host = host ? host : "";

    let port = "1080";
    const proxyPart = host.match(/:([0-9]+$)/);
    if (proxyPart) {
      host = host.slice(0, proxyPart.index);
      port = proxyPart[1];
    }
    const portInt = parseInt(port);

    code += "    proxy: {\n";
    code += "        protocol: " + repr(protocol) + ",\n";
    code += "        host: " + repr(host) + ",\n";
    if (!isNaN(portInt)) {
      code += "        port: " + port + ",\n";
    } else {
      code += "        port: " + repr(port) + ",\n";
    }
    if (request.proxyAuth) {
      const [proxyUser, proxyPassword] = request.proxyAuth.split(/:(.*)/s, 2);
      code += "        auth: {\n";
      code += "            user: " + repr(proxyUser);
      if (proxyPassword !== undefined) {
        code += ",\n";
        code += "            password: " + repr(proxyPassword) + "\n";
      } else {
        code += "\n";
      }
      code += "        },\n";
    }
    if (code.endsWith(",\n")) {
      code = code.slice(0, -2);
      code += "\n";
    }
    code += "    },\n";
  }

  if (code.endsWith(",\n")) {
    code = code.slice(0, -2);
  }
  code += "\n}";
  return code;
};

export const _toNodeAxios = (
  request: Request,
  warnings?: Warnings
): [string, Warnings] => {
  warnings = warnings || [];

  let importCode = "const axios = require('axios');\n";
  const imports: Set<[string, string]> = new Set();

  let code = "";

  const hasSearchParams =
    request.query &&
    (!request.queryDict ||
      // https://stackoverflow.com/questions/42898009/multiple-fields-with-same-key-in-query-params-axios-request
      Object.values(request.queryDict).some((qv) => Array.isArray(qv)));
  if (hasSearchParams && request.query) {
    code += "const params = new URLSearchParams();\n";
    for (const [key, value] of request.query) {
      const val = value ? value : "";
      code += "params.append(" + repr(key) + ", " + repr(val) + ");\n";
    }
    code += "\n";
  }

  if (request.multipartUploads) {
    imports.add(["form-data", "FormData"]);
    code += "const form = new FormData();\n";
    for (const {
      name,
      filename,
      content,
      contentFile,
    } of request.multipartUploads) {
      code += "form.append(" + repr(name) + ", ";
      if (contentFile === "-") {
        code += "fs.readFileSync(0).toString()";
        imports.add(["fs", "fs"]);
      } else if (contentFile) {
        code += "fs.readFileSync(" + repr(contentFile) + ")";
        imports.add(["fs", "fs"]);
      } else {
        code += repr(content as string);
      }
      if (filename && filename !== name) {
        code += ", " + repr(filename);
      }
      code += ");\n";
    }
    code += "\n";
  }

  const method = request.method.toLowerCase();
  const methods = ["get", "delete", "head", "options", "post", "put", "patch"];
  code += "const response = await axios";
  if (methods.includes(method)) {
    code += "." + method;
  }
  code += "(";

  const url =
    request.queryDict || hasSearchParams
      ? request.urlWithoutQuery
      : request.url;

  // axios only supports posting data with these HTTP methods
  // You can also post data with OPTIONS, but that has to go in the config object
  const dataMethods = ["post", "put", "patch"];
  let needsConfig = !!(
    request.query ||
    request.queryDict ||
    request.headers ||
    request.auth ||
    request.multipartUploads ||
    (request.data && !dataMethods.includes(method)) ||
    request.timeout ||
    request.proxy
  );
  const needsData =
    dataMethods.includes(method) &&
    (request.data || request.multipartUploads || needsConfig);

  let dataString, commentedOutDataString;
  if (needsData) {
    code += "\n";
    code += "    " + repr(url) + ",\n";
    if (request.data) {
      try {
        [dataString, commentedOutDataString] = getDataString(request);
        if (!dataString) {
          dataString = repr(request.data);
        }
      } catch {
        dataString = repr(request.data);
      }
      if (commentedOutDataString) {
        code += "    // " + commentedOutDataString + ",\n";
      }
      code += "    " + dataString;
    } else if (request.multipartUploads) {
      code += "    form";
    } else if (needsConfig) {
      // TODO: right way to pass "no data"?
      code += "    ''";
    }
  } else {
    code += repr(url);
  }

  // getDataString() can delete a header, so we can end up with an empty config
  needsConfig = !!(
    request.query ||
    request.queryDict ||
    (request.headers && request.headers.length) ||
    request.auth ||
    request.multipartUploads ||
    (request.data && !dataMethods.includes(method)) ||
    request.timeout ||
    request.proxy
  );

  if (needsConfig) {
    const config = buildConfigObject(
      request,
      method,
      methods,
      dataMethods,
      !!hasSearchParams
    );
    if (needsData) {
      code += ",\n";
      for (const line of config.split("\n")) {
        code += "    " + line + "\n";
      }
    } else {
      code += ", ";
      code += config;
    }
  } else if (needsData) {
    code += "\n";
  }

  code += ");\n";

  for (const [imp, varName] of Array.from(imports).sort()) {
    importCode += "const " + varName + " = require(" + repr(imp) + ");\n";
  }

  return [importCode + "\n" + code, warnings];
};
export const toNodeAxiosWarn = (
  curlCommand: string | string[]
): [string, Warnings] => {
  const [request, warnings] = util.parseCurlCommand(curlCommand, supportedArgs);
  return _toNodeAxios(request, warnings);
};
export const toNodeAxios = (curlCommand: string | string[]): string => {
  return toNodeAxiosWarn(curlCommand)[0];
};
