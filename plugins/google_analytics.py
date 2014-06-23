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

import re
import urllib

# Config
friendlyName = "Google Analytics Cookie Parser"
description = "Parses Google Analytics cookies"
artifactTypes = ["cookie (created)", "cookie (accessed)"]
remoteLookups = 0
browser = "Chrome"
browserVersion = 1
version = "20140623"


def plugin(target_browser):
    utma_re = re.compile(r'(\d+)\.(\d+)\.(\d{10})\.(\d{10})\.(\d{10})\.(\d+)')  #
    utmb_re = re.compile(r'(\d+)\.(\d+)\.\d+\.(\d{10})')
    utmc_re = re.compile(r'(\d+)')
    utmv_re = re.compile(r'(\d+)\.\|?(.*)')
    utmz_re = re.compile(r'(\d+)\.(\d{10})\.(\d+)\.(\d+)')
    utmz_parameters_re = re.compile(r'(\d+)\.(\d{10})\.(\d+)\.(\d+)\.(.*)')
    utmz_extract_parameters_re = re.compile(r'(.+?)=(.+)')

    for item in target_browser.parsed_artifacts:
        if item.row_type in artifactTypes:
            if item.name == '__utma':
                # TODO: consider adding in extra rows for each timestamp in cookie?
                m = re.search(utma_re, item.value)
                if m:
                    item.interpretation = "Domain Hash: %s | Unique Visitor ID: %s | First Visit: %s | " \
                                          "Previous Visit: %s | Last Visit: %s | Number of Sessions: %s | " \
                                          "[Google Analytics Cookie]"\
                                          % (m.group(1), m.group(2), target_browser.friendly_date(m.group(3)),
                                             target_browser.friendly_date(m.group(4)),
                                             target_browser.friendly_date(m.group(5)), m.group(6))
            if item.name == '__utmb':
                m = re.search(utmb_re, item.value)
                if m:
                    item.interpretation = "Domain Hash: %s | Pages Viewed: %s | Last Visit: %s | " \
                                          "[Google Analytics Cookie]" \
                                          % (m.group(1), m.group(2), target_browser.friendly_date(m.group(3)))
            if item.name == '__utmc':
                m = re.search(utmc_re, item.value)
                if m:
                    item.interpretation = "Domain Hash: %s | [Google Analytics Cookie]" % (m.group(1))
            if item.name == '__utmv':
                m = re.search(utmv_re, item.value)
                if m:
                    item.interpretation = "Domain Hash: %s | Custom Values: %s | [Google Analytics Cookie]" \
                                          % (m.group(1), urllib.unquote_plus(m.group(2)))
            if item.name == '__utmz':
                m = re.search(utmz_re, item.value)
                if m:
                    derived = "Domain Hash: %s | Last Visit: %s | Sessions: %s | Sources: %s | " \
                              % (m.group(1), target_browser.friendly_date(m.group(2)), m.group(3), m.group(4))

                    p = re.search(utmz_parameters_re, item.value)

                    parameters = {}
                    raw_parameters = p.group(5)[3:]  # Strip off first 'utm' so later splitting will work
                    # print(raw_parameters)

                    #Parse out cookie fields
                    for pair in raw_parameters.split('|utm'):               # Split the cookie on the '|' delimiter
                        # print pair
                        rp = re.search(utmz_extract_parameters_re, pair)    # Split each parameter on the first '='
                        try:
                            parameters[rp.group(1)] = rp.group(2)           # Put the parameter name and value in hash
                        except AttributeError:
                            pass

                    #Ex: 38950847.1357762586.5.5.utmcsr=google.com|utmccn=(referral)|utmcmd=referral|utmcct=/reader/view
                    if parameters['cmd'] == 'referral':
                        if 'csr' in parameters and 'cct' in parameters:
                            derived += "Referrer: %s%s | " % (parameters['csr'], parameters['cct'])
                        if parameters['ccn'] != '(referral)':
                            derived += "Ad Campaign Info: %s | " % (urllib.unquote_plus(parameters['ccn']))

                    #Ex: 120910874.1368486805.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided)
                    elif parameters['cmd'] == 'organic':
                        derived += "Last Type of Access: %s | " % (parameters['cmd'])
                        if 'ctr' in parameters:
                            derived += "Search keywords: %s | " % (urllib.unquote_plus(parameters['ctr']))
                        if parameters['ccn'] != '(organic)':
                            derived += "Ad Campaign Info: %s | " % (parameters['ccn'])

                    #Ex: 27069237.1369840721.3.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)
                    elif parameters['cmd'] != 'none' and parameters['ccn'] == '(direct)':
                        derived += "Last Type of Access: %s | " % (urllib.unquote_plus(parameters['ccn']))
                        if 'ctr' in parameters:
                            derived += "Search keywords: %s | " % (urllib.unquote_plus(parameters['ctr']))

                    # Otherwise, just print out all the fields
                    else:
                        if 'csr' in parameters:
                            derived += "Last Source Site: %s | " % (parameters['csr'])
                        if 'ccn' in parameters:
                            derived += "Ad Campaign Info: %s | " % (urllib.unquote_plus(parameters['ccn']))
                        if 'cmd' in parameters:
                            derived += "Last Type of Access: %s | " % (parameters['cmd'])
                        if 'ctr' in parameters:
                            derived += "Keyword(s) from Search that Found Site: %s | " % (parameters['ctr'])
                        if 'cct' in parameters:
                            derived += "Path to the page on the site of the referring link: %s | " % (parameters['cct'])

                    derived += "[Google Analytics Cookie] "
                    item.interpretation = derived