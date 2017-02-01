import hindsight
import bottle
import json
import os
import sys

# This will be the main hindsight.AnalysisSession object that all the work will be done on
analysis_session = None


def get_plugins_info():
    # Get the path the 'plugins' folder and insert it into the system path
    plugin_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'plugins')
    sys.path.insert(0, plugin_path)

    plugin_descriptions = []

    # Get list of available plugins
    plugin_listing = os.listdir(plugin_path)

    for plugin in plugin_listing:
        if plugin[-3:] == ".py":
            description = {'file_name': plugin, 'friendly_name': None, 'version': None, 'error': None, 'error_msg': None}
            plugin = plugin.replace(".py", "")
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
    return plugin_descriptions


# Static Routes
@bottle.get('/static/<filename:re:.*\.(png|css|ico|svg|json|eot|svg|ttf|woff|woff2)>')
def images(filename):
    return bottle.static_file(filename, root='static')


@bottle.route('/')
def main_screen():

    global analysis_session
    analysis_session = hindsight.AnalysisSession()
    bottle_args = analysis_session.__dict__
    plugins_info = get_plugins_info()
    bottle_args['plugins_info'] = plugins_info
    return bottle.template('templates/run.tpl', bottle_args)


@bottle.route('/run', method='POST')
def do_run():
    # Get user selections from the UI
    ui_selected_decrypts = bottle.request.forms.getall('selected_decrypts')
    analysis_session.selected_plugins = bottle.request.forms.getall('selected_plugins')
    analysis_session.profile_path = bottle.request.forms.get('profile_path')
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
    import StringIO
    strIO = StringIO.StringIO()
    strIO.write(analysis_session.generate_sqlite())
    strIO.seek(0)
    bottle.response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; charset=UTF-8'
    bottle.response.headers['Content-Disposition'] = 'attachment; filename=text.xls'
    return strIO.read()


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
    bottle.run(host='localhost', port=8080, debug=True)

if __name__ == "__main__":
    main()
