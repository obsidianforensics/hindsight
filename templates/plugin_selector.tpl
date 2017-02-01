<div class="plugin-container">
    <div class="header-box">Plugin Selector</div>
    <div class="selection-box">
    <table>
    %  for plugin in plugins_info:
    %     fn = plugin['file_name']
    %     frn = plugin['friendly_name']
    %     ver = plugin['version']
    %     error = plugin['error']
    %     error_msg = plugin['error_msg']
    %     if error == 'import':
            <tr>
                <td align=center><img src="static/error.png" title="{{error_msg}}" width=16></td>
                <td>{{frn}} <span class="version-text">[v{{ver}}]</span></td>
            </tr>
    %     else:
            <tr>
                <td><input type="checkbox" name="selected_plugins" value="{{fn}}" checked></td>
                <td>{{frn}} <span class="version-text">[v{{ver}}]</span></td>
            </tr>
    %     end
    %  end
    </table>
    </div>
</div>