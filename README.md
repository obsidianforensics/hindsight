hindsight
=========

Internet history forensics for Google Chrome/Chromium

Hindsight is a free tool for analyzing the browsing history of the Google Chrome web browser.  It can collect a number of different types of Chrome artifacts, including URLs, download history, bookmarks, autofill records, HTTP cookies, and Local Storage records (HTML5 cookies).  Once the data is extracted from each file, it is correlated with data from other history files and placed in a timeline.

There is a user guide in the documentation folder that covers many topics, but the info below should get you started:

Example usage:  \> C:\\hindsight.py -i "C:\Users\Ryan\AppData\Local\Google\Chrome\User Data\Default" -o test_case

Command Line Options:

| Option         | Description                                             |
| -------------- | ------------------------------------------------------- |
| -i or --input  | Path to the Chrome(ium) "Default" directory |
| -o or --output | Name of the output file (without extension) |
| -f or --format | Output format (default is XLSX, other options are SQLite and JSON) |
| -l or --log	 | Location Hindsight should log to (will append if exists) |
| -m or --mode   | Output mode (what to do if output file already exists).  Only works for SQLite. |
| -h or --help   | Shows these options and the default Chrome data locations |

The Chrome data folder default locations are:
* WinXP:   \[userdir\]\Local Settings\Application Data\Google\Chrome\User Data\Default\
* Vista/7/8: \[userdir\]\AppData\Local\Google\Chrome\User Data\Default\
* Linux:   \[userdir\]/.config/google-chrome/Default/
* OS X:    \[userdir\]/Library/Application Support/Google/Chrome/Default/

