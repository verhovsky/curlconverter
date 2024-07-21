import type { TreeCursor, SyntaxNode } from "@lezer/common";
import type { GlobalConfig } from "./curl/opts.js";
import type { Request } from "./Request.js";

export type Warnings = [string, string][];

export function warnf(global: GlobalConfig, warning: [string, string]) {
  global.warnings.push(warning);
}

function underline(
  node: SyntaxNode | TreeCursor,
  from: number,
  to: number,
  curlCommand: string,
): string {
  if (from === to) {
    to++;
  }

  // TODO: \r ?
  let lineStart = from;
  if (from > 0) {
    // If it's -1 we're on the first line
    lineStart = curlCommand.lastIndexOf("\n", from - 1) + 1;
  }

  let underlineLength = to - from;
  let lineEnd = curlCommand.indexOf("\n", from);
  if (lineEnd === -1) {
    lineEnd = curlCommand.length;
  } else if (lineEnd < to) {
    // Add extra "^" past the end of a line to signal that the node continues
    underlineLength = lineEnd - from + 1;
  }

  const line = curlCommand.slice(lineStart, lineEnd);
  const underline = " ".repeat(from - lineStart) + "^".repeat(underlineLength);
  return line + "\n" + underline;
}

export function underlineCursor(node: TreeCursor, curlCommand: string): string {
  return underline(node, node.from, node.to, curlCommand);
}

export function underlineNode(node: SyntaxNode, curlCommand?: string): string {
  return "";
  // doesn't include leading whitespace
  // const command = node.toTree().topNode;
  // let from = node.from;
  // let to = node.to;
  // if (!curlCommand) {
  //   curlCommand = command.text;
  //   from -= command.from;
  //   to -= command.from;
  // }
  // return underline(node, from, to, curlCommand);
}

export function underlineNodeEnd(
  node: SyntaxNode,
  curlCommand?: string,
): string {
  return "";
  // doesn't include leading whitespace
  // const command = node.tree.rootNode;
  // let from = node.from;
  // let to = node.to;
  // if (!curlCommand) {
  //   curlCommand = command.text;
  //   from -= command.from;
  //   to -= command.from;
  // }
  // if (from === to) {
  //   to++;
  // }

  // // TODO: \r ?
  // let lineStart = from;
  // if (from > 0) {
  //   // If it's -1 we're on the first line
  //   lineStart = curlCommand.lastIndexOf("\n", to - 1) + 1;
  // }

  // const underlineStart = Math.max(from, lineStart);
  // const underlineLength = to - underlineStart;
  // let lineEnd = curlCommand.indexOf("\n", to);
  // if (lineEnd === -1) {
  //   lineEnd = curlCommand.length;
  // }

  // const line = curlCommand.slice(lineStart, lineEnd);
  // const underline =
  //   " ".repeat(underlineStart - lineStart) + "^".repeat(underlineLength);
  // return line + "\n" + underline;
}

export interface Support {
  // multipleRequests?: boolean; // Why call this function?
  multipleUrls?: boolean;
  dataReadsFile?: boolean;
  queryReadsFile?: boolean;
  cookieFiles?: boolean;
}

export function warnIfPartsIgnored(
  request: Request,
  warnings: Warnings,
  support?: Support,
) {
  if (request.urls.length > 1 && !support?.multipleUrls) {
    warnings.push([
      "multiple-urls",
      "found " +
        request.urls.length +
        " URLs, only the first one will be used: " +
        request.urls
          .map((u) => JSON.stringify(u.originalUrl.toString()))
          .join(", "),
    ]);
  }
  if (request.dataReadsFile && !support?.dataReadsFile) {
    warnings.push([
      "unsafe-data",
      // TODO: better wording. Could be "body:" too
      "the generated data content is wrong, " +
        // TODO: might not come from "@"
        JSON.stringify("@" + request.dataReadsFile) +
        " means read the file " +
        JSON.stringify(request.dataReadsFile),
    ]);
  }
  if (request.urls[0].queryReadsFile && !support?.queryReadsFile) {
    warnings.push([
      "unsafe-query",
      "the generated URL query string is wrong, " +
        JSON.stringify("@" + request.urls[0].queryReadsFile) +
        " means read the file " +
        JSON.stringify(request.urls[0].queryReadsFile),
    ]);
  }
  if (request.cookieFiles && !support?.cookieFiles) {
    warnings.push([
      "cookie-files",
      "passing a file for --cookie/-b is not supported: " +
        request.cookieFiles.map((c) => JSON.stringify(c.toString())).join(", "),
    ]);
  }
}
