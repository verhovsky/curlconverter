import { GlobalConfig, OperationConfig } from "./curl/cfgable";
import URL from "url";

import nunjucks from "nunjucks";

import parser from "./bash-parser.js";
import {
  parseArgs,
  strdup,
  HTTPREQ_GET,
  HTTPREQ_HEAD,
  HTTPREQ_MIMEPOST,
  HTTPREQ_SIMPLEPOST,
  CURL_HTTP_VERSION_2_0,
  CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE,
  CURL_HTTP_VERSION_3,
  CURLAUTH_DIGEST,
} from "./curl/getparam.js";

const env = nunjucks.configure(["templates/"], {
  // set folders with templates
  autoescape: false,
});
env.addFilter("isArr", (something: any): boolean => Array.isArray(something));
env.addFilter(
  "isString",
  (something: any): boolean => typeof something === "string"
);

// TODO: this type doesn't work.
function has<T, K extends PropertyKey>(
  obj: T,
  prop: K
): obj is T & Record<K, unknown> {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

export class CCError extends Error {}

function pushProp<Type>(
  obj: { [key: string]: Type[] },
  prop: string,
  value: Type
) {
  if (!has(obj, prop)) {
    // TODO: I have no idea what
    // Type 'never[]' is not assignable to type 'never'.
    // means
    (obj[prop] as Type[]) = [];
  }
  obj[prop].push(value);
  return obj;
}

interface _LongShort {
  name?: string; // added dynamically
  type: "string" | "number" | "bool";
  expand?: boolean;
  removed?: string;
}

interface LongShort {
  name: string;
  type: "string" | "number" | "bool";
  expand?: boolean;
  removed?: string;
}

interface _LongOpts {
  [key: string]: _LongShort;
}
interface LongOpts {
  [key: string]: LongShort | null;
}
interface ShortOpts {
  [key: string]: string;
}

type Query = Array<[string, string | null]>;
interface QueryDict {
  [key: string]: string | null | Array<string | null>;
}

type Headers = Array<[string, string | null]>;

type Cookie = [string, string];
type Cookies = Array<Cookie>;

interface ParsedArguments {
  request?: string; // the HTTP method
  data?: string[];
  "data-binary"?: string[];
  "data-ascii"?: string[];
  "data-raw"?: string[];
  "data-urlencode"?: string[];
  json?: string[];
  [key: string]: any;
}

interface Request {
  url: string;
  urlWithoutQuery: string;
  query?: Query;
  queryDict?: QueryDict;
  method: string;
  headers?: Headers;
  stdin?: string;
  input?: string;
  multipartUploads?: [string, string][];
  auth?: [string, string];
  cookies?: Cookies;
  compressed?: boolean;
  isDataBinary?: boolean;
  isDataRaw?: boolean;
  digest?: boolean;
  dataArray?: string[];
  data?: string;
  insecure?: boolean;
  cert?: string | [string, string];
  cacert?: string;
  capath?: string;
  proxy?: string;
  proxyAuth?: string;
  timeout?: string;
  followRedirects?: boolean;
  output?: string;
  http2?: boolean;
  http3?: boolean;
}

function toBoolean(opt: string): boolean {
  if (opt.startsWith("no-disable-")) {
    return true;
  }
  if (opt.startsWith("disable-") || opt.startsWith("no-")) {
    return false;
  }
  return true;
}

const parseWord = (str: string): string => {
  const BACKSLASHES = /\\./gs;
  const unescapeChar = (m: string) => (m.charAt(1) === "\n" ? "" : m.charAt(1));
  return str.replace(BACKSLASHES, unescapeChar);
};
const parseSingleQuoteString = (str: string): string => {
  const BACKSLASHES = /\\(\n|')/gs;
  const unescapeChar = (m: string) => (m.charAt(1) === "\n" ? "" : m.charAt(1));
  return str.slice(1, -1).replace(BACKSLASHES, unescapeChar);
};
const parseDoubleQuoteString = (str: string): string => {
  const BACKSLASHES = /\\(\n|\\|")/gs;
  const unescapeChar = (m: string) => (m.charAt(1) === "\n" ? "" : m.charAt(1));
  return str.slice(1, -1).replace(BACKSLASHES, unescapeChar);
};
// ANSI-C quoted strings look $'like this'.
// Not all shells have them but bash does
// https://www.gnu.org/software/bash/manual/html_node/ANSI_002dC-Quoting.html
//
// https://git.savannah.gnu.org/cgit/bash.git/tree/lib/sh/strtrans.c
const parseAnsiCString = (str: string): string => {
  const ANSI_BACKSLASHES =
    /\\(\\|a|b|e|E|f|n|r|t|v|'|"|\?|[0-7]{1,3}|x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|c.)/gs;
  const unescapeChar = (m: string) => {
    switch (m.charAt(1)) {
      case "\\":
        return "\\";
      case "a":
        return "\x07";
      case "b":
        return "\b";
      case "e":
      case "E":
        return "\x1B";
      case "f":
        return "\f";
      case "n":
        return "\n";
      case "r":
        return "\r";
      case "t":
        return "\t";
      case "v":
        return "\v";
      case "'":
        return "'";
      case '"':
        return '"';
      case "?":
        return "?";
      case "c":
        // bash handles all characters by considering the first byte
        // of its UTF-8 input and can produce invalid UTF-8, whereas
        // JavaScript stores strings in UTF-16
        if (m.codePointAt(2)! > 127) {
          throw new CCError(
            "non-ASCII control character in ANSI-C quoted string: '\\u{" +
              m.codePointAt(2)!.toString(16) +
              "}'"
          );
        }
        // If this produces a 0x00 (null) character, it will cause bash to
        // terminate the string at that character, but we return the null
        // character in the result.
        return m[2] === "?"
          ? "\x7F"
          : String.fromCodePoint(
              m[2].toUpperCase().codePointAt(0)! & 0b00011111
            );
      case "x":
      case "u":
      case "U":
        // Hexadecimal character literal
        // Unlike bash, this will error if the the code point is greater than 10FFFF
        return String.fromCodePoint(parseInt(m.slice(2), 16));
      case "0":
      case "1":
      case "2":
      case "3":
      case "4":
      case "5":
      case "6":
      case "7":
        // Octal character literal
        return String.fromCodePoint(parseInt(m.slice(1), 8) % 256);
      default:
        // There must be a mis-match between ANSI_BACKSLASHES and the switch statement
        throw new CCError(
          "unhandled character in ANSI-C escape code: " + JSON.stringify(m)
        );
    }
  };

  return str.slice(2, -1).replace(ANSI_BACKSLASHES, unescapeChar);
};

function toVal(node: any): string {
  // TODO: typing node is hard because of the browser/nodejs import difference
  switch (node.type) {
    case "word":
    case "simple_expansion": // TODO: handle variables properly downstream
      return parseWord(node.text);
    case "string":
      return parseDoubleQuoteString(node.text);
    case "raw_string":
      return parseSingleQuoteString(node.text);
    case "ansii_c_string":
      return parseAnsiCString(node.text);
    case "concatenation":
      // item[]=1 turns into item=1 if we don't do this
      // https://github.com/tree-sitter/tree-sitter-bash/issues/104
      // TODO: type `n` if you type `node`
      if (node.children.every((n: any) => n.type === "word")) {
        return node.text;
      }
      return node.children.map(toVal).join("");
    default:
      // console.error(curlCommand)
      // console.error(curlArgs.rootNode.toString())
      throw new CCError(
        "unexpected argument type " +
          JSON.stringify(node.type) +
          '. Must be one of "word", "string", "raw_string", "ascii_c_string", "simple_expansion" or "concatenation"'
      );
  }
}

const tokenize = (curlCommand: string): [string[], string?, string?] => {
  const curlArgs = parser.parse(curlCommand);
  // The AST must be in a nice format, i.e.
  // (program
  //   (command
  //     name: (command_name (word))
  //     argument+: (
  //       word |
  //       string ('') |
  //       raw_string ("") |
  //       ansii_c_string ($'') |
  //       simple_expansion (variable_name))))
  //
  // TODO: support strings with variable expansions inside
  // TODO: support prefixed variables, e.g. "MY_VAR=hello curl example.com"
  // TODO: get only named children?
  if (curlArgs.rootNode.type !== "program") {
    // TODO: better error message.
    throw new CCError(
      "expected a 'program' top-level AST node, got " +
        curlArgs.rootNode.type +
        " instead"
    );
  }

  if (curlArgs.rootNode.childCount < 1 || !curlArgs.rootNode.children) {
    // TODO: better error message.
    throw new CCError('empty "program" node');
  }

  // Get the curl call AST node. Skip comments
  let command, stdin, input;
  for (const programChildNode of curlArgs.rootNode.children) {
    if (programChildNode.type === "comment") {
      continue;
    } else if (programChildNode.type === "command") {
      command = programChildNode;
      // TODO: if there are more `command` nodes,
      // warn that everything after the first one is ignored
      break;
    } else if (programChildNode.type === "redirected_statement") {
      if (!programChildNode.childCount) {
        throw new CCError("got empty 'redirected_statement' AST node");
      }
      let redirect;
      [command, redirect] = programChildNode.children;
      if (command.type !== "command") {
        throw new CCError(
          "got 'redirected_statement' AST node whose first child is not a 'command', got " +
            command.type +
            " instead"
        );
      }
      if (programChildNode.childCount < 2) {
        throw new CCError(
          "got 'redirected_statement' AST node with only one child - no redirect"
        );
      }
      if (redirect.type === "file_redirect") {
        stdin = toVal(redirect.namedChildren[0]);
      } else if (redirect.type === "heredoc_redirect") {
        // heredoc bodies are children of the parent program node
        // https://github.com/tree-sitter/tree-sitter-bash/issues/118
        if (redirect.namedChildCount < 1) {
          throw new CCError(
            "got 'redirected_statement' AST node with heredoc but no heredoc start"
          );
        }
        const heredocStart = redirect.namedChildren[0].text;
        const heredocBody = programChildNode.nextNamedSibling;
        if (!heredocBody) {
          throw new CCError(
            "got 'redirected_statement' AST node with no heredoc body"
          );
        }
        // TODO: herestrings and heredocs are different
        if (heredocBody.type !== "heredoc_body") {
          throw new CCError(
            "got 'redirected_statement' AST node with heredoc but no heredoc body, got " +
              heredocBody.type +
              " instead"
          );
        }
        // TODO: heredocs do variable expansion and stuff
        if (heredocStart.length) {
          input = heredocBody.text.slice(0, -heredocStart.length);
        } else {
          // this shouldn't happen
          input = heredocBody.text;
        }
        // Curl remove newlines when you pass any @filename including @- for stdin
        input = input.replace(/\n/g, "");
      } else if (redirect.type === "herestring_redirect") {
        if (redirect.namedChildCount < 1 || !redirect.firstNamedChild) {
          throw new CCError(
            "got 'redirected_statement' AST node with empty herestring"
          );
        }
        // TODO: this just converts bash code to text
        input = redirect.firstNamedChild.text;
      } else {
        throw new CCError(
          "got 'redirected_statement' AST node whose second child is not one of 'file_redirect', 'heredoc_redirect' or 'herestring_redirect', got " +
            command.type +
            " instead"
        );
      }

      break;
    } else {
      // TODO: better error message.
      throw new CCError(
        "expected a 'command' or 'redirected_statement' AST node, instead got " +
          curlArgs.rootNode.children[0].type
      );
    }
  }
  if (!command) {
    // NOTE: if you add more node types in the `for` loop above, this error needs to be updated.
    // We would probably need to keep track of the node types we've seen.
    throw new CCError(
      "expected a 'command' or 'redirected_statement' AST node, only found 'comment' nodes"
    );
  }

  if (command.childCount < 1) {
    // TODO: better error message.
    throw new CCError('empty "command" node');
  }
  // TODO: add childrenForFieldName to tree-sitter node/web bindings and then
  // use that here instead
  // TODO: you can have variable_assignment before the actual command
  // MY_VAR=foo curl example.com
  const [cmdName, ...args] = command.children;
  if (cmdName.type !== "command_name") {
    // TODO: better error message.
    throw new CCError(
      "expected a 'command_name' AST node, got " + cmdName.type + " instead"
    );
  }

  return [[cmdName.text.trim(), ...args.map(toVal)], stdin, input];
};

export function parseQueryString(
  s: string | null
): [Query | null, QueryDict | null] {
  // if url is 'example.com?' => s is ''
  // if url is 'example.com'  => s is null
  if (!s) {
    return [null, null];
  }

  const asList: Query = [];
  for (const param of s.split("&")) {
    const [key, _val] = param.split(/=(.*)/s, 2);
    const val = _val === undefined ? null : _val;
    let decodedKey;
    let decodedVal;
    try {
      // https://url.spec.whatwg.org/#urlencoded-parsing recommends replacing + with space
      // before decoding.
      decodedKey = decodeURIComponent(key.replace(/\+/g, " "));
      decodedVal =
        val === null ? null : decodeURIComponent(val.replace(/\+/g, " "));
    } catch (e) {
      if (e instanceof URIError) {
        // Query string contains invalid percent encoded characters,
        // we cannot properly convert it.
        return [null, null];
      }
      throw e;
    }
    try {
      // If the query string doesn't round-trip, we cannot properly convert it.
      // TODO: this is too strict. Ideally we want to check how each runtime/library
      // percent encodes query strings. For example, a %27 character in the input query
      // string will be decoded to a ' but won't be re-encoded into a %27 by encodeURIComponent
      const percentEncodeChar = (c: string): string =>
        "%" + c.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase();
      // Match Python's urllib.parse.quote() behavior
      // https://stackoverflow.com/questions/946170/equivalent-javascript-functions-for-pythons-urllib-parse-quote-and-urllib-par
      const percentEncode = (s: string): string =>
        encodeURIComponent(s).replace(/[()*!']/g, percentEncodeChar); // .replace('%20', '+')
      const roundTripKey = percentEncode(decodedKey);
      const roundTripVal =
        decodedVal === null ? null : percentEncode(decodedVal);
      // If the original data used %20 instead of + (what requests will send), that's close enough
      if (
        (roundTripKey !== key && roundTripKey.replace(/%20/g, "+") !== key) ||
        (roundTripVal !== null &&
          roundTripVal !== val &&
          roundTripVal.replace(/%20/g, "+") !== val)
      ) {
        return [null, null];
      }
    } catch (e) {
      if (e instanceof URIError) {
        return [null, null];
      }
      throw e;
    }
    asList.push([decodedKey, decodedVal]);
  }

  // Group keys
  const asDict: QueryDict = {};
  let prevKey = null;
  for (const [key, val] of asList) {
    if (prevKey === key) {
      (asDict[key] as Array<string | null>).push(val);
    } else {
      if (!has(asDict, key)) {
        (asDict[key] as Array<string | null>) = [val];
      } else {
        // If there's a repeated key with a different key between
        // one of its repetitions, there is no way to represent
        // this query string as a dictionary.
        return [asList, null];
      }
    }
    prevKey = key;
  }

  // Convert lists with 1 element to the element
  for (const [key, val] of Object.entries(asDict)) {
    if ((val as Array<string | null>).length === 1) {
      asDict[key] = (val as Array<string | null>)[0];
    }
  }

  return [asList, asDict];
}

function buildRequest(_global: GlobalConfig, config: OperationConfig): Request {
  // TODO: handle multiple URLs
  if (!config.urls || !config.urls.length) {
    // TODO: better error message (could be parsing fail)
    throw new CCError("no URL specified!");
  }
  let url = config.urls[config.urls.length - 1].url;

  const headers: Headers = [];
  if (config.headers) {
    for (const header of config.headers) {
      if (header.includes(":")) {
        const [name, value] = header.split(/:(.*)/s, 2);
        if (!value.trim()) {
          headers.push([name, null]);
        } else {
          headers.push([name, value.replace(/^ /, "")]);
        }
      } else if (header.includes(";")) {
        const [name] = header.split(/;(.*)/s, 2);
        headers.push([name, ""]);
      }
    }
  }
  const lowercase =
    headers.length > 0 && headers.every((h) => h[0] === h[0].toLowerCase());

  let cookies;
  const cookieHeaders = headers.filter((h) => h[0].toLowerCase() === "cookie");
  if (cookieHeaders.length === 1 && cookieHeaders[0][1] !== null) {
    const parsedCookies = parseCookiesStrict(cookieHeaders[0][1]);
    if (parsedCookies) {
      cookies = parsedCookies;
    }
  } else if (cookieHeaders.length === 0) {
    // If there is a Cookie header, --cookies is ignored
    if (config.cookies) {
      // TODO: a --cookie without a = character reads from it as a filename
      const cookieString = config.cookies.join(";");
      _setHeaderIfMissing(headers, "Cookie", cookieString, lowercase);
      cookies = parseCookies(cookieString);
    }
  }

  if (config.useragent) {
    _setHeaderIfMissing(headers, "User-Agent", config.useragent, lowercase);
  }

  if (config.referer) {
    // referer can be ";auto" or followed by ";auto", we ignore that.
    const referer = config.referer.replace(/;auto$/, "");
    if (referer) {
      _setHeaderIfMissing(headers, "Referer", referer, lowercase);
    }
  }

  // curl expects you to uppercase methods always. If you do -X PoSt, that's what it
  // will send, but most APIs will helpfully uppercase what you pass in as the method.
  // TODO: read curl's source to figure out precedence rules.
  let method = "GET";
  if (config.httpreq === HTTPREQ_HEAD) {
    method = "HEAD";
  } else if (config.httpreq === HTTPREQ_GET) {
    method = "GET";
  } else if (
    // TODO: what is the difference
    config.httpreq === HTTPREQ_MIMEPOST ||
    config.httpreq === HTTPREQ_SIMPLEPOST
  ) {
    method = "GET";
  } else if (has(config, "request") && config.request !== "null") {
    // Safari adds `-Xnull` if it can't determine the request type
    method = config.request as string;
  } else if (config.urls[0].infile) {
    // TODO: what if some urls have it and some don't, can't just check the first one
    // --upload-file '' doesn't do anything.
    method = "PUT";
  } else if (
    (has(config, "postfields") || has(config, "mime")) &&
    !config.use_httpget
  ) {
    method = "POST";
  }

  const urlObject = URL.parse(url); // eslint-disable-line
  // if GET request with data, convert data to query string
  // NB: the -G flag does not change the http verb. It just moves the data into the url.
  // TODO: this probably has a lot of mismatches with curl
  if (config.use_httpget) {
    urlObject.query = urlObject.query ? urlObject.query : "";
    if (has(config, "data") && config.data !== undefined) {
      let urlQueryString = "";

      if (url.indexOf("?") < 0) {
        url += "?";
      } else {
        urlQueryString += "&";
      }

      urlQueryString += config.postfields.map((pf) => pf.content).join("&"); // TODO: lots of filtering and stuff
      urlObject.query += urlQueryString;
      // TODO: url and urlObject will be different if url has an #id
      url += urlQueryString;
      delete config.data;
    }
  }
  if (urlObject.query && urlObject.query.endsWith("&")) {
    urlObject.query = urlObject.query.slice(0, -1);
  }
  const [queryAsList, queryAsDict] = parseQueryString(urlObject.query);
  const useParsedQuery =
    queryAsList &&
    queryAsList.length &&
    queryAsList.every((p) => p[1] !== null);
  // Most software libraries don't let you distinguish between a=&b= and a&b,
  // so if we get an `a&b`-type query string, don't bother.
  let urlWithoutQuery;
  if (useParsedQuery) {
    urlObject.search = null; // Clean out the search/query portion.
    urlWithoutQuery = URL.format(urlObject);
  } else {
    urlWithoutQuery = url; // TODO: rename?
  }

  const request: Request = { url, method, urlWithoutQuery };
  if (useParsedQuery) {
    request.query = queryAsList;
    if (queryAsDict) {
      request.queryDict = queryAsDict;
    }
  }

  if (cookies) {
    // generators that use .cookies need to do
    // deleteHeader(request, 'cookie')
    request.cookies = cookies;
  }

  if (config.encoding) {
    request.compressed = true;
  }

  // TODO: all of these could be specified in the same command.
  // They also need to maintain order.
  // TODO: do all of these allow @file?
  let data;
  if (config.postfields) {
    if (config.postfields[0].mode === "json") {
      _setHeaderIfMissing(
        headers,
        "Content-Type",
        "application/json",
        lowercase
      );
      _setHeaderIfMissing(headers, "Accept", "application/json", lowercase);
    } else {
      _setHeaderIfMissing(
        headers,
        "Content-Type",
        "application/x-www-form-urlencoded",
        lowercase
      );
    }
    data = config.postfields;
  } else if (config.mime) {
    request.multipartUploads = [];
    for (const multipartArgument of config.mime) {
      // -F is the most complicated option, we just assume it looks
      // like key=value and some generators handle value being @filepath
      // TODO: https://curl.se/docs/manpage.html#-F
      const [key, value] = multipartArgument.split(/=(.*)/s, 2);
      request.multipartUploads.push([key, value || ""]);
    }
  }

  if (headers.length > 0) {
    for (let i = headers.length - 1; i >= 0; i--) {
      if (headers[i][1] === null) {
        // TODO: ideally we should generate code that explicitly unsets the header too
        headers.splice(i, 1);
      }
    }
    request.headers = headers;
  }

  if (config.userpwd) {
    const [user, pass] = config.userpwd.split(/:(.*)/s, 2);
    request.auth = [user, pass || ""];
  }
  if (config.authtype !== undefined && config.authtype & CURLAUTH_DIGEST) {
    request.digest = true;
  }
  if (data) {
    if (data.length > 1) {
      request.dataArray = data;
      request.data = data.join(config.json ? "" : "&");
    } else {
      request.data = data[0];
    }
  }

  if (config.insecure_ok) {
    request.insecure = true;
  }
  // TODO: if the URL doesn't start with https://, curl doesn't verify
  // certificates, etc.
  if (config.cert) {
    // --key has no effect if --cert isn't passed
    request.cert = config.key ? [config.cert, config.key] : config.cert;
  }
  if (config.cacert) {
    request.cacert = config.cacert;
  }
  if (config.capath) {
    request.capath = config.capath;
  }
  if (config.proxy) {
    request.proxy = config.proxy;
    if (config.proxyuserpwd) {
      request.proxyAuth = config.proxyuserpwd;
    }
  }
  // TODO: is int, which can be 0
  if (config.timeout) {
    request.timeout = config.timeout.toString();
  }
  if (config.followlocation) {
    request.followRedirects = true;
  }
  if (config.urls[0].outfile) {
    request.output = config.urls[0].outfile;
  }

  if (
    config.httpversion === CURL_HTTP_VERSION_2_0 ||
    config.httpversion === CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE
  ) {
    request.http2 = true;
  } else if (config.httpversion === CURL_HTTP_VERSION_3) {
    request.http3 = true;
  }

  return request;
}

function buildRequests(_global: GlobalConfig): Request[] {
  return (_global.configs || []).map((c) => buildRequest(_global, c));
}

const parseCurlCommand = (
  curlCommand: string | string[]
): [
  Request[],
  GlobalConfig,
  number,
  string | null | undefined,
  string | null | undefined
] => {
  const [args, stdin, input] = Array.isArray(curlCommand)
    ? [curlCommand, null, null]
    : tokenize(curlCommand);

  const cmdName = args[0];
  if (typeof cmdName === "undefined") {
    if (Array.isArray(curlCommand)) {
      throw new CCError("no arguments provided");
    } else {
      throw new CCError("failed to parse input");
    }
  }
  if (cmdName.trim() !== "curl") {
    const shortenedCmdName =
      cmdName.length > 30 ? cmdName.slice(0, 27) + "..." : cmdName;
    if (cmdName.startsWith("curl ")) {
      throw new CCError(
        'command should begin with a single token "curl" but instead begins with ' +
          JSON.stringify(shortenedCmdName)
      );
    } else {
      throw new CCError(
        'command should begin with "curl" but instead begins with ' +
          JSON.stringify(shortenedCmdName)
      );
    }
  }

  const _global: GlobalConfig = { configs: [{}] };
  const result = parseArgs(args, _global);
  const requests = buildRequests(_global);
  return [requests, _global, result, stdin, input];
};

// Gets the first header, matching case-insensitively
const getHeader = (
  request: Request,
  header: string
): string | null | undefined => {
  if (!request.headers) {
    return undefined;
  }
  const lookup = header.toLowerCase();
  for (const [h, v] of request.headers) {
    if (h.toLowerCase() === lookup) {
      return v;
    }
  }
  return undefined;
};

const _hasHeader = (headers: Headers, header: string): boolean => {
  const lookup = header.toLowerCase();
  for (const h of headers) {
    if (h[0].toLowerCase() === lookup) {
      return true;
    }
  }
  return false;
};

const hasHeader = (request: Request, header: string): boolean | undefined => {
  if (!request.headers) {
    return;
  }
  return _hasHeader(request.headers, header);
};

const _setHeaderIfMissing = (
  headers: Headers,
  header: string,
  value: string,
  lowercase: boolean | number = false
): boolean => {
  if (_hasHeader(headers, header)) {
    return false;
  }
  headers.push([lowercase ? header.toLowerCase() : header, value]);
  return true;
};
const setHeaderIfMissing = (
  request: Request,
  header: string,
  value: string,
  lowercase: boolean | number = false
) => {
  if (!request.headers) {
    return;
  }
  return _setHeaderIfMissing(request.headers, header, value, lowercase);
};

const _deleteHeader = (headers: Headers, header: string) => {
  const lookup = header.toLowerCase();
  for (let i = headers.length - 1; i >= 0; i--) {
    if (headers[i][0].toLowerCase() === lookup) {
      headers.splice(i, 1);
    }
  }
};

const deleteHeader = (request: Request, header: string) => {
  if (!request.headers) {
    return;
  }
  return _deleteHeader(request.headers, header);
};

const countHeader = (request: Request, header: string) => {
  let count = 0;
  const lookup = header.toLowerCase();
  for (const h of request.headers || []) {
    if (h[0].toLowerCase() === lookup) {
      count += 1;
    }
  }
  return count;
};

const parseCookiesStrict = (cookieString: string): Cookies | null => {
  const cookies: Cookies = [];
  for (let cookie of cookieString.split(";")) {
    cookie = cookie.replace(/^ /, "");
    const [name, value] = cookie.split(/=(.*)/s, 2);
    if (value === undefined) {
      return null;
    }
    cookies.push([name, value]);
  }
  return cookies;
};

const parseCookies = (cookieString: string): Cookies => {
  const cookies: Cookies = [];
  for (let cookie of cookieString.split(";")) {
    cookie = cookie.trim();
    if (!cookie) {
      continue;
    }
    const [name, value] = cookie.split(/=(.*)/s, 2);
    cookies.push([name, value || ""]);
  }
  return cookies;
};

export {
  parseCurlCommand,
  parseArgs,
  buildRequests,
  getHeader,
  hasHeader,
  countHeader,
  setHeaderIfMissing,
  deleteHeader,
  has,
};

export type { LongOpts, ShortOpts, Request, Cookie, Cookies, Query, QueryDict };
