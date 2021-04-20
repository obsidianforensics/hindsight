<div class="results-artifacts-container">
    <div class="header-box">Parsed Artifacts</div>
    <div class="selection-box">
         <center>
         <table width=100%>
            <tr class="results-row">
                <td align="right" width=65%>Detected {{browser_type}} version:</td>
                <td align="right">{{display_version}}</td>
                <td width=10%></td>
            </tr>
         % display_items = list(artifacts_display.keys())
         % display_order = ['Archived History', 'History', 'History_downloads', 'Cache', 'Application Cache', 'Media Cache', 'GPUCache', 'Cookies', 'Local Storage', 'Bookmarks', 'Autofill', 'Login Data', 'Preferences', 'Extensions', 'Extension Cookies' ]
         % while len(display_order) > 0:
         %   if display_order[0] in display_items:
            <tr class="results-row">
                <td align="right">{{artifacts_display[display_order[0]]}}:</td>
                <td align="right">{{artifacts_counts.get(display_order[0], 0)}}</td>
                <td width=10%></td>

            </tr>
         %       display_items.remove(display_order[0])
         %   end
         %   display_order.pop(0)
         % end

         % for artifact in display_items:
            <tr class="results-row">
                <td align="right">{{artifacts_display[artifact]}}:</td>
                <td align="right">{{artifacts_counts.get(artifact, 0)}}</td>
                <td width=10%></td>
            </tr>
         % end
         </table>
         </center>
    </div>
</div>