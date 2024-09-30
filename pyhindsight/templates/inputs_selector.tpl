                    <div class="inputs-container">

                        <!-- taken from: http://www.tek-tips.com/viewthread.cfm?qid=577844 //-->
                        <script language="JavaScript">
                        function toggle(rowtoshow)
                         {
                            var browsers = [
                            % for browser in available_input_types:
                                            "{{browser}}",
                            % end
                            ]
                             //first hide all rows
                             var length_of_browsers = browsers.length
                             for (i=0; i < length_of_browsers; i++)
                             {
                            eval("document.getElementById(\"description-"+browsers[i]+"\").style.display='none'");
                            }
                             //now see which row to show
                             if (rowtoshow!="") {
                                 obj_id = "description-".concat(rowtoshow);
                                 obj_id;
                                 obj=document.getElementById(obj_id);
                                 obj.style.display='';
                                 }
                         }

                        function inputDefaults() {
                            var x = document.forms["run"]["profile_path"].value;
                            if (x == null || x == "" || x == "required" || x == "C:\\Path\\To\\Input\\Data") {
                                document.forms["run"]["profile_path"].value = ""
                                document.forms["run"]["profile_path"].style.color = "black";
                                document.forms["run"]["profile_path"].style.backgroundColor = "white";
                                return false;
                            }
                        }

                        function cacheInput() {
                            var x = document.forms["run"]["cache_path"].value;
                            if (x == null || x == "" || x == "(optional - only needed if outside of the profile path)") {
                                document.forms["run"]["cache_path"].value = ""
                                document.forms["run"]["cache_path"].style.color = "black";
                                document.forms["run"]["cache_path"].style.backgroundColor = "white";
                                return false;
                            }
                        }

                        </script>

                        <div class="header-box">Inputs</div>
                        <div class="selection-box">
                        <table padding=15>
                            <tr>
                                <td class="input-option">
                                    <b>Input Type:</b>
                                    <select name="browser_type" onchange="toggle(this.value)">
                                        <option value="Chrome">Chrome</option>
                                        <option value="Brave">Brave</option>
                                    </select>
                                </td>
                                <td style="text-align: right;">
                                    &nbsp&nbsp <b>Profile Path:</b> <input class="input-path" name="profile_path" type="text" onfocus=inputDefaults() size=56 value='C:\Path\To\Input\Data'/>&nbsp&nbsp&nbsp
                                </td>
                            </tr>
                            <tr>
                                <td class="input-option">
                                </td>
                                <td style="text-align: right;">
                                    &nbsp&nbsp <b>Cache Path:</b> <input class="input-path" name="cache_path" type="text" onfocus=cacheInput() size=56 value='(optional - only needed if outside of the profile path)'/>&nbsp&nbsp&nbsp
                                </td>
                            </tr>
                            <tr id="description-Chrome">
                                <td colspan=2 class="input-description">
                                    <table>
                                        <tr><td>
                                            <b>Description:</b> Chrome is a free web browser from Google that runs on Windows, macOS, Linux, ChromeOS, iOS, and Android.
                                            Each user's web history and configuration information is stored under their user directory in a <i>profile</i>. Each user can have one or more profiles,
                                            so there may be multiple sets of browser data on the system.
                                            <br /><br />
                                        </td>
                                        <td>
                                            <img src="static/chrome_logo.svg" width=75>
                                        </td></tr>
                                        <tr><td colspan=2 valign="bottom">
                                            <b>Available Decryption:</b>
                                                % import sys
                                                % if available_decrypts['windows'] == 1 and sys.platform == 'win32':
                                                    Windows<input type="checkbox" name="selected_decrypts" value="windows" checked>
                                                % else:
                                                    Windows <img src="static/error.png" title="Decryption of Chrome data on Windows uses native APIs (via the 'win32crypt' Python module). In order to do this, Hindsight must be run on the Windows computer, under the target user account." width=16>
                                                % end

                                                % if available_decrypts['mac'] == 1 and sys.platform == 'darwin':
                                                    Mac<input type="checkbox" name="selected_decrypts" value="mac" checked>
                                                % else:
                                                    Mac <img src="static/error.png" title="Decryption of Chrome data on Mac uses native APIs (via the 'keyring' Python module). In order to do this, Hindsight must be run on the Mac computer, under the target user account." width=16>
                                                % end

                                                % if available_decrypts['linux'] == 1:
                                                    Linux<input type="checkbox" name="selected_decrypts" value="linux">
                                                % else:
                                                    Linux <img src="static/error.png" title="Decryption of Chrome data from Linux uses the 'Crypto.Cipher.AES' and 'Crypto.Protocol.KDF' Python modules. Decryption can be done offline, on any examiner OS. Attempting to decypt non-Linux Chrome data with this method with cause errors." width=16>
                                                % end
                                        </td>
                                        </tr>
                                    </table>
                                    <br />
                                    <b>Default Profile Locations:</b>
                                    <table>
                                        <tr><td class="input-option">Windows (Vista - 11):</td><td> \[userdir]\AppData\Local\Google\Chrome\User Data\Default</td></tr>
                                        <tr><td class="input-option">Linux:</td><td> \[userdir]/.config/google-chrome/Default</td></tr>
                                        <tr><td class="input-option">OSX/macOS:</td><td> \[userdir]/Library/Application Support/Google/Chrome/Default</td></tr>
                                        <tr><td class="input-option">iOS:</td><td> \Applications\com.google.chrome.ios\Library\Application Support\Google\Chrome</td></tr>
                                        <tr><td class="input-option">Android:</td><td> /userdata/data/com.android.chrome/app_chrome</td></tr>
                                        <tr><td class="input-option" colspan=2>In a running Chrome browser, go to chrome://version/ to see the Profile Path information</td></tr>
                                    </table>
                                </td>
                            </tr>
                            <tr id="description-Brave" style="display:none">
                                <td colspan=2 class="input-description">
                                    <table>
                                        <tr><td>
                                            <b>Description:</b> Brave is a free web browser that aims to "speed up the web, stop bad ads and pay publishers." Brave has an integrated ad-blocker and an optional ad replacement system that pays both ad companies and the user in BAT. Brave also claims to offer a faster and more private browsing experience by blocking trackers and intrusive ads.

                                        </td>
                                        <td>
                                            <img src="static/brave_logo.png" width=75>
                                        </td></tr>
                                    </table>
                                    <br />
                                    <b>Default Locations:</b>
                                    <table>
                                        <tr><td class="input-option">Vista/7/8/10:</td><td> \[userdir]\AppData\Roaming\brave</td></tr>
                                        <tr><td class="input-option">Linux:</td><td> \[userdir]/.config/brave</td></tr>
                                        <tr><td class="input-option">OSX/macOS:</td><td> \[userdir]/Library/Application Support/brave</td></tr>
                                    </table>
                                </td>
                            </tr>
                            <tr><td></td><td></td></tr>
                        </table>
                        </div>
                    </div>
