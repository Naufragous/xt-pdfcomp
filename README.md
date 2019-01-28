# PDF Compatibility X-Tension

The built-in Oracle viewer component used by X-Ways Forensics does not print
some PDF documents properly. There seems to be an issue with the font
information. Some prints can have missing text or square boxes instead of
letters.

This viewer extension uses the Ghostscript library to internally preprocess
the PDF files in a way that prevents this bug from happening.

## Installation
* Download the [32-bit](https://github.com/Naufragous/xt-pdfcomp/releases/tag/9.26-x86) or
[64-bit](https://github.com/Naufragous/xt-pdfcomp/releases/tag/9.26-x64) Release.
* Move the gsdll32.dll or gsdll64.dll to your X-Ways Forensics directory.
<br>**Important:** gsdll32.dll and xwforensics.exe (or gsdll64.dll and xwforensics64.exe)
must be in the same directory.
* Load the X-Tension in X-Ways Forensics (*Options -> Viewer Programs -> Load viewer X-Tensions*).
* Turn the X-Tension on by pressing the *XT* Mode Button while previewing a PDF file.

## Building from source
* Open the Visual Studio Command Prompt
(e.g. *VS 2015 x86 Native Tools* or *VS 2015 x64 Native Tools*).
* Run **nmake win32** or **nmake win64** in the project directory.

## License
GNU Affero General Public License v3.0.

## Links
* [X-Ways Forensics](http://www.x-ways.net/forensics/)
* [Ghostscript](https://www.ghostscript.com/)
