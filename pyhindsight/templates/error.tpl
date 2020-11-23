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
                                <h1>Error</h1>
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
                    <center>
                        <table width=70%>
                            <tr>
                              <td><h2>Hindsight has encountered an error and cannot continue</h2>
                              Error: {{fatal_error}}<br><br></td>
                            </tr>
                            <tr>
                              <td><center>
                                <input type="button" value="Start New Analysis Session" class="button" onclick="location.href='/';" style="width:40%" />
                              </center></td>
                            </tr>
                        </table>
                    </center>
                </td>
            </tr>
        </table>
        </center>

% include('templates/footer.tpl')