#!/usr/bin/env python3
"""Checks the internal links of the built book (scripts/ci.sh book).

Usage: scripts/check-book-links.py [BOOK_DIR]   (default: target/book)

Every relative `href` of an `<a>` and `src` of an `<img>` in every HTML
page must name a file inside the book, and a `#fragment` must name an id
in that page. Links with a scheme (https:, mailto:, ...) are not followed.
404.html is skipped: it resolves its links against the site root.
Prints one line per broken link and exits non-zero if there is any.
"""

import html.parser
import os
import sys
import urllib.parse


class Page(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.links: list[tuple[int, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v for k, v in attrs if v is not None}
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "a" and "name" in a:
            self.ids.add(a["name"])
        url = a.get("href") if tag == "a" else a.get("src") if tag == "img" else None
        if url is not None:
            self.links.append((self.getpos()[0], url))


def parse(path: str, cache: dict[str, Page]) -> Page:
    if path not in cache:
        page = Page()
        with open(path, encoding="utf-8") as f:
            page.feed(f.read())
        page.close()
        cache[path] = page
    return cache[path]


def main() -> int:
    root = os.path.realpath(sys.argv[1] if len(sys.argv) > 1 else "target/book")
    if not os.path.isfile(os.path.join(root, "index.html")):
        print(f"check-book-links: no built book in {root}", file=sys.stderr)
        return 1
    cache: dict[str, Page] = {}
    broken = 0
    pages = 0
    for dirpath, _, files in os.walk(root):
        for name in sorted(files):
            path = os.path.join(dirpath, name)
            if not name.endswith(".html") or path == os.path.join(root, "404.html"):
                continue
            pages += 1
            for line, url in parse(path, cache).links:
                problem = check(root, path, url, cache)
                if problem:
                    broken += 1
                    print(f"{os.path.relpath(path, root)}:{line}: {url}: {problem}")
    if broken:
        print(f"check-book-links: {broken} broken links", file=sys.stderr)
        return 1
    print(f"check-book-links: {pages} pages, all internal links resolve")
    return 0


def check(root: str, page: str, url: str, cache: dict[str, Page]) -> str | None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme or parts.netloc:
        return None
    if not parts.path:
        target = page
    else:
        target = os.path.realpath(
            os.path.join(os.path.dirname(page), urllib.parse.unquote(parts.path))
        )
        if os.path.commonpath([root, target]) != root:
            return "points outside the book"
        if os.path.isdir(target):
            target = os.path.join(target, "index.html")
        if not os.path.isfile(target):
            return "no such file in the book"
    if parts.fragment:
        if not target.endswith(".html"):
            return "fragment on a file that is not a page"
        if urllib.parse.unquote(parts.fragment) not in parse(target, cache).ids:
            return "no such anchor"
    return None


if __name__ == "__main__":
    sys.exit(main())
