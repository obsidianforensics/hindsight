<div class="results-plugins-container">
    <div class="header-box">Plugin Results</div>
    <div class="selection-box">
         <table width=100%>
         % for results in plugin_results:
            <tr class="results-row">
                <td align="right" width=350>{{plugin_results[results][0]}} <span class="version-text">[v{{plugin_results[results][1]}}]</span>:</td>
                <td align="center">- {{plugin_results[results][2]}} -</td>
            </tr>
         % end
          </table>
    </div>
</div>