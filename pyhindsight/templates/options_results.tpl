<div class="results-options-container">
    <div class="header-box">Summary</div>
    <div class="selection-box">
         <table width=100%>
            <tr><td align="right" colspan=2>Input Path:</td><td>{{input_path}}</td></tr>
            <tr><td align="right" colspan=2>Input Type:</td><td>{{browser_type}}</td></tr>
            <tr><td align="right" colspan=2>Profile Paths:</td><td></td></tr>
            <tr><td></td><td colspan=2>
                <ul>
            % for path in profile_paths:
                    <li>{{path}}</li>
            % end
                </ul>
            </td></tr>
          </table>
    </div>
</div>