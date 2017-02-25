import hindsight
import bottle
import json
import os
import sys
import webbrowser

# This will be the main hindsight.AnalysisSession object that all the work will be done on
analysis_session = None


def get_plugins_info():

    plugin_descriptions = []

    # Useful when Hindsight is run from a different directory than where the file is located
    real_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    if real_path not in sys.path:
        sys.path.insert(0, real_path)

    completed_plugins = []

    # Loop through all paths, to pick up all potential locations for plugins
    for potential_path in sys.path:
        # If a subdirectory exists called 'plugins' at the current path, continue on
        potential_plugin_path = os.path.join(potential_path, 'plugins')
        if os.path.isdir(potential_plugin_path):
            try:
                # Insert the current plugin location to the system path, so we can import plugin modules by name
                sys.path.insert(0, potential_plugin_path)

                # Get list of available plugins and run them
                plugin_listing = os.listdir(potential_plugin_path)

                for plugin in plugin_listing:
                    if plugin[-3:] == ".py":
                        description = {'file_name': plugin, 'friendly_name': None, 'version': None, 'error': None, 'error_msg': None}
                        plugin = plugin.replace(".py", "")

                        # Check to see if we've already run this plugin (likely from a different path)
                        if plugin in completed_plugins:
                            continue

                        try:
                            module = __import__(plugin)
                            description['friendly_name'] = module.friendlyName
                            description['version'] = module.version
                            try:
                                module.plugin()
                            except ImportError, e:
                                description['error'] = 'import'
                                description['error_msg'] = e
                                continue

                        except Exception, e:
                            description['error'] = 'other'
                            description['error_msg'] = e
                            continue

                        finally:
                            plugin_descriptions.append(description)
                            completed_plugins.append(plugin)

            except Exception as e:
                # logging.debug(' - Error loading plugins ({})'.format(e))
                print '  - Error loading plugins'
            finally:
                # Remove the current plugin location from the system path, so we don't loop over it again
                sys.path.remove(potential_plugin_path)
    return plugin_descriptions


# Static Routes
@bottle.get('/static/<filename:re:.*\.(png|css|ico|svg|json|eot|svg|ttf|woff|woff2)>')
def images(filename):
    return bottle.static_file(filename, root=STATIC_PATH)


@bottle.route('/')
def main_screen():

    global analysis_session
    analysis_session = hindsight.AnalysisSession()
    bottle_args = analysis_session.__dict__
    plugins_info = get_plugins_info()
    bottle_args['plugins_info'] = plugins_info
    return bottle.template(os.path.join('templates', 'run.tpl'), bottle_args)


@bottle.route('/run', method='POST')
def do_run():
    # Get user selections from the UI
    ui_selected_decrypts = bottle.request.forms.getall('selected_decrypts')
    analysis_session.selected_plugins = bottle.request.forms.getall('selected_plugins')
    analysis_session.profile_path = bottle.request.forms.get('profile_path')
    analysis_session.cache_path = bottle.request.forms.get('cache_path')
    analysis_session.browser_type = bottle.request.forms.get('browser_type')
    analysis_session.timezone = bottle.request.forms.get('timezone')
    analysis_session.log_path = bottle.request.forms.get('log_path')

    if 'windows' in ui_selected_decrypts:
        analysis_session.available_decrypts['windows'] = 1
    else:
        analysis_session.available_decrypts['windows'] = 0

    if 'mac' in ui_selected_decrypts:
        analysis_session.available_decrypts['mac'] = 1
    else:
        analysis_session.available_decrypts['mac'] = 0

    if 'linux' in ui_selected_decrypts:
        analysis_session.available_decrypts['linux'] = 1
    else:
        analysis_session.available_decrypts['linux'] = 0

    analysis_session.run()
    analysis_session.run_plugins()
    return bottle.redirect('/results')


@bottle.route('/results')
def display_results():
    return bottle.template('templates/results.tpl', analysis_session.__dict__)


@bottle.route('/sqlite')
def generate_sqlite():
    temp_output = '.tempdb'
    try:
        os.remove(temp_output)
    except:
        # temp file deletion failed
        pass

    analysis_session.generate_sqlite(output_object=temp_output)
    import StringIO
    str_io = StringIO.StringIO()
    with open(temp_output, 'rb') as f:
        str_io.write(f.read())

    try:
        os.remove(temp_output)
    except:
        # temp file deletion failed
        pass

    bottle.response.headers['Content-Type'] = 'application/x-sqlite3'
    bottle.response.headers['Content-Disposition'] = 'attachment; filename={}.sqlite'.format(analysis_session.output_name)
    str_io.seek(0)
    return str_io.read()


@bottle.route('/xlsx')
def generate_xlsx():
    import StringIO
    strIO = StringIO.StringIO()
    analysis_session.generate_excel(strIO)
    # strIO.write()
    strIO.seek(0)
    bottle.response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; charset=UTF-8'
    bottle.response.headers['Content-Disposition'] = 'attachment; filename={}.xlsx'.format(analysis_session.output_name)
    return strIO.read()


@bottle.route('/json')
def generate_json():
    import StringIO
    strIO = StringIO.StringIO()
    strIO.write(json.dumps(analysis_session, cls=hindsight.MyEncoder, indent=4))
    strIO.seek(0)
    bottle.response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; charset=UTF-8'
    bottle.response.headers['Content-Disposition'] = 'attachment; filename={}.json'.format(analysis_session.output_name)
    return strIO.read()


def main():

    print hindsight.banner

    global STATIC_PATH
    STATIC_PATH = 'static'

    # Loop through all paths in system path, to pick up all potential locations for templates and static files.
    # Paths can get weird when the program is run from a different directory, or when the packaged exe is unpacked.
    for potential_path in sys.path:
        potential_template_path = potential_path
        if os.path.isdir(potential_template_path):
            # Insert the current plugin location to the system path, so bottle can find the templates
            bottle.TEMPLATE_PATH.insert(0, potential_template_path)

        potential_static_path = os.path.join(potential_path, 'static')
        if os.path.isdir(potential_static_path):
            STATIC_PATH = potential_static_path

    # webbrowser.open("http://localhost:8080")
    bottle.run(host='localhost', port=8080, debug=True)

if __name__ == "__main__":
    main()
