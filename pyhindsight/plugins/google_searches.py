###################################################################################################
#
# google_searches.py
#   Extracts parameters from Google search URLs
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################

# Config
friendlyName = u'Google Searches'
description = u'Extracts parameters from Google search URLs'
artifactTypes = (u'url',)
remoteLookups = 0
browser = u'Chrome'
browserVersion = 1
version = u'20160912'
parsedItems = 0


def plugin(analysis_session=None):
    import re
    import urllib
    if analysis_session is None:
        return

    google_re = re.compile(r'^http(s)?://www\.google(\.[A-z]{2,3})?(\.com)?(\.[A-z]{2,3})?/(search\?|webhp\?|#q)(.*)$')
    extract_parameters_re = re.compile(r'(.+?)=(.+)')
    qdr_re = re.compile(r'(s|n|h|d|w|m|y)(\d{0,9})')
    tbs_qdr_re = re.compile(r'qdr:(s|n|h|d|w|m|y)(\d{0,9})')
    tbs_cd_re = re.compile(r'cd_min:(\d{1,2}/\d{1,2}/\d{2,4}),cd_max:(\d{1,2}/\d{1,2}/\d{2,4})')
    global parsedItems
    parsedItems = 0

    time_abbr = {u's': u'second', u'n': u'minute', u'h': u'hour', u'd': u'day', 
                 u'w': u'week', u'm': u'month', u'y': u'year'}

    for item in analysis_session.parsed_artifacts:
        if item.row_type.startswith(artifactTypes):
            m = re.search(google_re, item.url)
            if m:
                parameters = {}
                raw_parameters = m.group(6)

                if m.group(5) == u'#q':
                    raw_parameters = u'q' + raw_parameters

                #Parse out search parameters
                # TODO: Figure out # vs & separators
                raw_parameters = raw_parameters.replace(u'#q=', u'&q=')  # Replace #q with &q so it will split correctly
                for pair in raw_parameters.split(u'&'):          # Split the query on the '&' delimiter
                    # print pair
                    p = re.search(extract_parameters_re, pair)  # Split each parameter on the first '='
                    try:
                        parameters[p.group(1)] = urllib.unquote_plus(p.group(2))  # Put parameter name and value in hash
                    except AttributeError:
                        pass

                if u'q' in parameters:  # 'q' parameter must be present for rest of parameters to be parsed
                    derived = u'Searched for "{}" [ '.format(parameters[u'q'])

                    if u'pws' in parameters:
                        derived += u'Google personalization turned '
                        derived += (u'on | ' if parameters[u'pws'] == u'1' else u'off | ')

                    if u'num' in parameters:
                        derived += u'Showing %s results per page' % (parameters[u'num'])

                    if u'filter' in parameters:
                        derived += u'Omitted/Similar results filter '
                        derived += (u'on | ' if parameters[u'filter'] == u'1' else u'off | ')

                    if u'btnl' in parameters:
                        derived += u'"I\'m Feeling Lucky" search '
                        derived += (u'on | ' if parameters[u'btnl'] == u'1' else u'off | ')

                    if u'safe' in parameters:
                        derived += u'SafeSearch: {} | '.format(parameters[u'safe'])

                    if u'as_qdr' in parameters:
                        qdr = re.search(qdr_re, parameters[u'as_qdr'])
                        if qdr:
                            if qdr.group(1) and qdr.group(2):
                                derived += u'Results in the past {} {}s | '.format(qdr.group(2), time_abbr[qdr.group(1)])
                            elif qdr.group(1):
                                derived += u'Results in the past {} | '.format(time_abbr[qdr.group(1)])

                    if u'tbs' in parameters:
                        tbs_qdr = re.search(tbs_qdr_re, parameters[u'tbs'])
                        if tbs_qdr:
                            if tbs_qdr.group(1) and tbs_qdr.group(2):
                                derived += u'Results in the past {} {}s | '.format(tbs_qdr.group(2), time_abbr[tbs_qdr.group(1)])
                            elif tbs_qdr.group(1):
                                derived += u'Results in the past {} | '.format(time_abbr[tbs_qdr.group(1)])
                        elif parameters[u'tbs'][:3].lower() == u'cdr':
                            tbs_cd = re.search(tbs_cd_re, parameters[u'tbs'])
                            if tbs_cd:
                                derived += u'Results in custom range {} - {} | '.format(tbs_cd.group(1), tbs_cd.group(2))
                        elif parameters[u'tbs'][:3].lower() == u'dfn':
                            derived += u'Dictionary definition | '
                        elif parameters[u'tbs'][:3].lower() == u'img':
                            derived += u'Sites with images | '
                        elif parameters[u'tbs'][:4].lower() == u'clir':
                            derived += u'Translated sites | '
                        elif parameters[u'tbs'][:2].lower() == u'li':
                            derived += u'Verbatim results | '
                        elif parameters[u'tbs'][:3].lower() == u'vid':
                            derived += u'Video results | '
                        elif parameters[u'tbs'][:3].lower() == u'nws':
                            derived += u'News results | '
                        elif parameters[u'tbs'][:3].lower() == u'sbd':
                            derived += u'Sorted by date | '

                    if u'bih' in parameters and 'biw' in parameters:
                        derived += u'Browser screen {}x{} | '.format(parameters[u'biw'], parameters[u'bih'])

                    if u'pq' in parameters:
                        if parameters[u'pq'] != parameters[u'q']:  # Don't include PQ if same as Q to save space
                            derived += u'Previous query: "{}" | '.format(parameters[u'pq'])

                    if u'oq' in parameters:
                        if parameters[u'oq'] != parameters[u'q']:  # Don't include OQ if same as Q to save space
                            if u'aq' in parameters:
                                aq_re = re.compile(r'^\d$')
                                ordinals = [u'first', u'second', u'third', u'fourth', u'fifth',
                                            u'sixth', u'seventh', u'eighth', u'ninth']
                                if re.search(aq_re, parameters[u'aq']):
                                    derived += u'Typed "{}" before clicking on the {} suggestion | ' \
                                               .format(parameters[u'oq'], ordinals[int(parameters[u'aq'])])
                            else:
                                derived += u'Typed "{}" before clicking on a suggestion | '.format(parameters[u'oq'])

                    if u'as_sitesearch' in parameters:
                        derived += u'Search only {} | '.format(parameters[u'as_sitesearch'])

                    if u'as_filetype' in parameters:
                        derived += u'Show only {} files | '.format(parameters[u'as_filetype'])

                    if u'sourceid' in parameters:
                        derived += u'Using {}  | '.format(parameters[u'sourceid'])

                    # if u'ei' in parameters:
                    #     derived += u'Using %s  | ' % (parameters[u'sourceid'])

                    if derived[-2:] == u'[ ':
                        derived = derived[:-2]
                    elif derived[-3:] == u' | ':
                        derived = derived[:-3] + u']'

                    item.interpretation = derived
                parsedItems += 1

    # Description of what the plugin did
    return u'{} searches parsed'.format(parsedItems)
