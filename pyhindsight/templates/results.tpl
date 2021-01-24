% include('templates/header.tpl')

        <center>
        <table class="layout-table">
            <tr valign="top">
                <td colspan=2 class="results-td">
                    <table width=100%>
                        <tr>
                            <td class="h-logo-cell" rowspan=2 width=105>
                                <img src="static/h.png" width=105>
                            </td>
                            <td class="top-name">
                                <h1>Results</h1>
                            </td>
                        </tr>
                        <tr>
                            <td class="top-tagline">Hindsight - Web Artifact Analysis</td>
                        </tr>
                    </table>
                </td>

            </tr>
            <tr valign="top">
                <td class="results-td">
                    % include('templates/options_results.tpl')
                    <br />
                    % include('templates/plugin_results.tpl')
                </td>
                <td class="results-td">
                    % include('templates/parsed_artifacts.tpl')
                    <br />
                    <center>

                    <table width=100%>
                    <tr>
                      <td align="left" width=33%><input type="button" value="Save XLSX" class="button" onclick="location.href='/xlsx';" style="width:100%" /></td>
                      <td align="center" width=33%><input type="button" value="Save JSONL" class="button" onclick="location.href='/jsonl';" style="width:100%" /></td>
                      <td align="right" width=33%><input type="button" value="Save SQLite DB" class="button" onclick="location.href='/sqlite';" style="width:100%" /></td>
                    </tr>
                    <tr>
                      <td colspan="3">
                        <input type="button" class="button" onclick="location.href='/sqlite-view';" style="width:100%"
                          % if not js_installed:
                             value="View SQLite DB in Browser &#9888;" disabled title="&#9888; Incomplete Installation: Install javascript dependencies to view SQLite in the browser."
                          % else:
                            value="View SQLite DB in Browser"
                          % end
                          />
                      </td>
                    </tr>
                    <tr>
                      <td colspan=3>
                        <input type="button" value="Start New Analysis Session" class="button" onclick="location.href='/';" style="width:100%" />
                      </td>
                    </tr>
                    </table>
                    </center>

                </td>
            </tr>
        </table>
        </center>

% include('templates/footer.tpl')
