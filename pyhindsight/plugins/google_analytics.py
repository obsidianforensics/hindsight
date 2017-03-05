###################################################################################################
#
# google_analytics.py
#   Interpret Google Analytics cookies
#
# References:
#   Jon S. Nelson (http://www.dfinews.com/article/google-analytics-cookies-and-forensic-implications)
#
# Plugin Author: Ryan Benson (ryan@obsidianforensics.com)
#
###################################################################################################


# Config
friendlyName = "Google Analytics Cookie Parser"
description = "Parses Google Analytics cookies"
artifactTypes = u'cookie'
remoteLookups = 0
browser = "all"
browserVersion = 1
version = "20170130"
parsedItems = 0


def plugin(analysis_session=None):
    from pyhindsight.utils import friendly_date
    import re
    import urllib

    utma_re = re.compile(r'(\d+)\.(\d+)\.(\d{10})\.(\d{10})\.(\d{10})\.(\d+)')
    utmb_re = re.compile(r'(\d+)\.(\d+)\.\d+\.(\d{10})')
    utmc_re = re.compile(r'(\d+)')
    utmv_re = re.compile(r'(\d+)\.\|?(.*)')
    utmz_re = re.compile(r'(\d+)\.(\d{10})\.(\d+)\.(\d+)')
    utmz_parameters_re = re.compile(r'(\d+)\.(\d{10})\.(\d+)\.(\d+)\.(.*)')
    utmz_extract_parameters_re = re.compile(r'(.+?)=(.+)')
    ga_re = re.compile(r'GA1\.\d+\.(\d+)\.(\d{10})$')

    global parsedItems
    parsedItems = 0

    for item in analysis_session.parsed_artifacts:
        if item.row_type.startswith(artifactTypes):
            if item.name == u'__utma':
                # TODO: consider adding in extra rows for each timestamp in cookie?
                m = re.search(utma_re, item.value)
                if m:
                    item.interpretation = u'Domain Hash: {} | Unique Visitor ID: {} | First Visit: {} | ' \
                                          u'Previous Visit: {} | Last Visit: {} | Number of Sessions: {} | ' \
                                          u'[Google Analytics Cookie]'\
                        .format(m.group(1), m.group(2), friendly_date(m.group(3)),
                                friendly_date(m.group(4)), friendly_date(m.group(5)),
                                m.group(6))
                    parsedItems += 1
            if item.name == u'__utmb':
                m = re.search(utmb_re, item.value)
                if m:
                    item.interpretation = u'Domain Hash: {} | Pages Viewed: {} | Last Visit: {} | ' \
                                          u'[Google Analytics Cookie]' \
                                          .format(m.group(1), m.group(2), friendly_date(m.group(3)))
                    parsedItems += 1
            if item.name == u'__utmc':
                m = re.search(utmc_re, item.value)
                if m:
                    item.interpretation = u'Domain Hash: {} | [Google Analytics Cookie]'.format(m.group(1))
                    parsedItems += 1
            if item.name == u'__utmv':
                m = re.search(utmv_re, item.value)
                if m:
                    item.interpretation = u'Domain Hash: {} | Custom Values: {} | [Google Analytics Cookie]' \
                                          .format(m.group(1), urllib.unquote_plus(m.group(2)))
                    parsedItems += 1
            if item.name == u'__utmz':
                m = re.search(utmz_re, item.value)
                if m:
                    derived = u'Domain Hash: {} | Last Visit: {} | Sessions: {} | Sources: {} | ' \
                              .format(m.group(1), friendly_date(m.group(2)), m.group(3), m.group(4))
                    parsedItems += 1
                    p = re.search(utmz_parameters_re, item.value)

                    parameters = {}
                    raw_parameters = p.group(5)[3:]  # Strip off first 'utm' so later splitting will work
                    # print(raw_parameters)

                    #Parse out cookie fields
                    for pair in raw_parameters.split(u'|utm'):               # Split the cookie on the '|' delimiter
                        # print pair
                        rp = re.search(utmz_extract_parameters_re, pair)    # Split each parameter on the first '='
                        try:
                            parameters[rp.group(1)] = rp.group(2)           # Put the parameter name and value in hash
                        except AttributeError:
                            pass
                    if u'cmd' in parameters:
                        #Ex: 38950847.1357762586.5.5.utmcsr=google.com|utmccn=(referral)|utmcmd=referral|utmcct=/reader/view
                        if parameters[u'cmd'] == u'referral':
                            if u'csr' in parameters and u'cct' in parameters:
                                derived += u'Referrer: {}{} | '.format(parameters[u'csr'], parameters[u'cct'])
                            if parameters[u'ccn'] != u'(referral)':
                                derived += u'Ad Campaign Info: {} | '.format(urllib.unquote_plus(parameters[u'ccn']))

                        #Ex: 120910874.1368486805.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided)
                        elif parameters[u'cmd'] == u'organic':
                            derived += u'Last Type of Access: {} | '.format(parameters[u'cmd'])
                            if u'ctr' in parameters:
                                derived += u'Search keywords: {} | '.format(urllib.unquote_plus(parameters[u'ctr']))
                            if parameters[u'ccn'] != u'(organic)':
                                derived += u'Ad Campaign Info: %s | '.format(parameters['ccn'])

                        #Ex: 27069237.1369840721.3.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)
                        elif parameters[u'cmd'] != u'none' and parameters[u'ccn'] == u'(direct)':
                            derived += u'Last Type of Access: {} | '.format(urllib.unquote_plus(parameters[u'ccn']))
                            if u'ctr' in parameters:
                                derived += u'Search keywords: {} | '.format(urllib.unquote_plus(parameters[u'ctr']))

                    # Otherwise, just print out all the fields
                    else:
                        if u'csr' in parameters:
                            derived += u'Last Source Site: {} | '.format(parameters[u'csr'])
                        if u'ccn' in parameters:
                            derived += u'Ad Campaign Info: {} | '.format(urllib.unquote_plus(parameters[u'ccn']))
                        if u'cmd' in parameters:
                            derived += u'Last Type of Access: {} | '.format(parameters[u'cmd'])
                        if u'ctr' in parameters:
                            derived += u'Keyword(s) from Search that Found Site: {} | '.format(parameters[u'ctr'])
                        if u'cct' in parameters:
                            derived += u'Path to the page on the site of the referring link: {} | '.format(parameters[u'cct'])

                    derived += u'[Google Analytics Cookie] '
                    item.interpretation = derived
            if item.name == u'_ga':
                m = re.search(ga_re, item.value)
                if m:
                    item.interpretation = u'Client ID: {}.{} | First Visit: {} | [Google Analytics Cookie]' \
                        .format(m.group(1), m.group(2), friendly_date(m.group(2)))
                    parsedItems += 1

    # Description of what the plugin did
    return u'{} cookies parsed'.format(parsedItems)
