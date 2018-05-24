# firMetrics.py -- a Python Module to pull FIR data
#   into a Google Sheets doc for Security Metric reporting
# -- Cole Hocking


#-------------------------------------------------------------------------------
import requests, json, gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime, timedelta
import pandas as pd

#-------------------------------------------------------------------------------
# Google Sheets API plugin class object 
# API Reference: http://gspread.readthedocs.io
#   The credentials are packed into a json file that can be referenced outside the module 
class GsObject(object):
    """
    A Google Sheets (gspread) class object to allow API integration with Google Sheets
    """
    def __init__(self, scope):
        """ Returns a GsObject with Sheets scope """
        self.scope = scope
        self.credentials = self.setCreds(scope)

    def getScope(self):
        """ Returns the current scope """ 
        return self.scope

    def setCreds(self, scope):
        """ set the credentials for the given scope """
        # TODO - verify your creds.json file; see README for link to tutorial on this
        return ServiceAccountCredentials.from_json_keyfile_name('../.creds.json', scope)

    def authCreds(self):
        """ Returns an onject with authorized credentials """ 
        return gspread.authorize(self.credentials)

#-------------------------------------------------------------------------------
# Global Variable Declaration

# Handling as globals for now
eventList = list() # a list of the incident objects
commentList = list() # a list of the comment objects
# rolling 90 day timestamp
rNinety = datetime.today() - timedelta(days=90)
NO_CLOSED_COMMENT = 1 # A label to indicate that a closed comment was not found for a closed event

# Event Frequency Counting Dictionary
# TODO - Some of these categories are custom; you may need to modify
cDict = {'Phishing': 0, 'Malware': 0, 'Data Loss': 0, 'Unavailability': 0, 'Compromise': 0, 'Reputation': 0, 'Social Engineering': 0, 'Known Vulnerability': 0, 'DoS/DDoS': 0, 'Security Assessment': 0, 'Botnet Callout': 0, 'Configuration Change': 0, 'Hardware Compromise': 0, 'Account Compromise': 0, 'Unidentified': 0} 
#-------------------------------------------------------------------------------

# Convert category numeric ID to correct FIR category
def categoryTable(idN):
    """
    Convert the numeric JSON categories to their names in FIR
    """ 
    # Note: when the category # is parsed by Python's interpreter, it is treated as type int
    # TODO - verify your categories and numbers, using the FIR API
    if idN == 1:
        cDict['Phishing'] += 1 
        return "Phishing"
    elif idN == 4:
        cDict['Malware'] += 1
        return "Malware"
    elif idN == 7:
        cDict['Data Loss'] += 1
        return "Data Loss"
    elif idN == 9:
        cDict['Unavailability'] += 1
        return "Unavailability"
    elif idN == 12:
        cDict['Compromise'] += 1
        return "Compromise"
    elif idN == 13:
        cDict['Reputation'] += 1
        return "Reputation"
    elif idN == 16:
        cDict['Social Engineering'] += 1 
        return "Social Engineering"
    elif idN == 18: 
        cDict['Known Vulnerability'] += 1
        return "Known Vulnerability"
    elif idN == 21:
        cDict['DoS/DDoS'] += 1
        return "DoS/DDoS"
    elif idN == 24:
        cDict['Security Assessment'] += 1
        return "Security Assessment"
    elif idN == 25:
        cDict['Botnet Callout'] += 1
        return "Botnet Callout"
    elif idN == 26:
        cDict['Configuration Change'] += 1
        return "Configuration Change"
    elif idN == 29:
        cDict['Hardware Compromise'] += 1 
        return "Hardware Compromise"
    elif idN == 30:
        cDict['Account Compromise'] += 1
        return "Account Compromise"
    else: 
        cDict['Unidentified'] += 1
        return "Unidentified"    

#-------------------------------------------------------------------------------

# Converts unicode object to datetime object for comparison
def convertTime(uTime):
    """
    Unicode to datetime conversion Function
    """
    try:
        # Strips the fractions of a second, if there are any.
        #   This method is used in place of the pandas datetime conversion method
        #   as this function will normalize the output format; which is useful for dictionary values
        #   The pandas library method is used elsewhere as it is better equipped for type conversion 
        dtObj = datetime.strptime(uTime, '%Y-%m-%dT%H:%M:%S')
        return dtObj

    except ValueError:
        # Throw a Formatting Error
        #   Note: the string formatter '%r' calls the 'repr' operation, which defaults to an unambiguous
        #   representation, rather than a readable one (such as '%s') 
        print "The object %r of type %r passed to convertTime() could not be converted to datetime." % (uTime, type(uTime))

#-------------------------------------------------------------------------------

# Close Date Function
def getCloseDate(link):
    """
    Return the date closed from the comment API
    """
    # The API for the comments
    # TODO - Replace with your FIR API token
    cApi = requests.get(link, headers={'Authorization': 'Token <your-token-here>'})
    
    if cApi.status_code == requests.codes.ok: # Verify the link is valid
        cEvents = cApi.json()
        # Comment events parsed as they are nested inside the "results" portion of the json object 
        for c in cEvents['results']:
            if c['action'] == 13: #13 is the 'Closed' action; note: "33" is remediated status 
                # TODO - update with your FIR server path
                tmpDict = {'commentID': c['id'], 'date': c['date'], 'incidentID': c['incident'].strip('https://your-FIR-server-path/api/incidents/'), 'action': c['action']}
                commentList.append(tmpDict) # Add the comment, with the appropriate identifiers, to the array of comments
            
        cLink = cEvents['next'] # The objects are listed page by page, so this will provide the link to the next page, until the value is null
        if cLink is not None: # None and null are synonymous in Python (in this case at least)
            getCloseDate(cLink)
        
    else: 
        # this will still throw an error, but a try catch block will not run in this instance
        print "There was a problem connecting to %r " % (events.url)
        raise ConnectionError

#-------------------------------------------------------------------------------

# Mean Time to Close 
def getMttc():
    """
    solves the MTTC between the open date in the incident API and the 'status changed to "Closed"' comment date
    """
    # initializes closeDate, otherwise throws a ref before assignment error
    closeDate = 0
    totalDays = 0.0 # to add up the closing deltas
    totalEvents = 0.0 # to divide the days for the mean
    mttc = 0.0 # Initializes the mttc to be acurate to the tenth decimal place

    for e in eventList:
        if e['status'] == "C":
            # assigns closeDate to 1, indicating we have a closed incident, but it needs a closed comment
            closeDate = NO_CLOSED_COMMENT
            # the date of the incident in the API is the open date 
            openDate = e['date'] 
            for c in commentList:
                if c['incidentID'] == e['id']:
                    closeDate = c['date'] #Match the closed comment to its incident
                    break # we found it, do not need to iterate through the rest of the comments
                else:
                    continue # we havent found it yet, keep going
            if closeDate == NO_CLOSED_COMMENT: # closed date has stayed 1, so we did not find a closed comment
                print "Close date not found for closed incident: %s." % (e['id'])
            else:
                # the conversion function in this module does not always work, but the pandas library appears to
                #   typecast each object correctly; a debugging session showed they are passed as diffent types
                #       for reasons unknown
                d1 = pd.to_datetime(closeDate) # Format the close date 
                d2 = pd.to_datetime(openDate) # Format the open date
                d3 = d1 - d2 # datetime objects can be subtracted because python libraries are awesome (sometimes)
                d3 = float(d3.days) #d3 is type datetime.delta, so format to int
                totalDays += d3 # add the number of days to the total; the dividend
                totalEvents += 1 # increment the number of events; the divior             

        else:
            continue # continue iterating through eventList, looking for more closed events until we find them all
    
    # Outputs to stdout to confirm the math is correct
    mttc = totalDays/totalEvents # calculate the mean
    print "Total Days: %s / Total Events: %s = Mean: %s" % (str(totalDays), str(totalEvents), str("%.1f" % mttc))
    return mttc #returns the mttc to be written to the google sheets doc
        
#-------------------------------------------------------------------------------

# Get the relevant info on 90 day rolling events
def getRelevantEventData(jEvents):
    """
    This function appends only the rolling 90 day events with the relevant info to the eventList array
    """
    for j in jEvents['results']: # parses the nested incidents contained in the results object    
        if convertTime(j['date']) >= rNinety: # Only grabs the rolling 90 day events
            tmpDict = {'category': categoryTable(j['category']), 'status': str(j['status']), 'date': j['date'], 'id': str(j['id'])}
            eventList.append(tmpDict) # append the events to the array
        else:
            continue 
    
#-------------------------------------------------------------------------------

# get the events from FIR
def getFirData(link):
    """
    This function parses the incident/event list to grab all of the FIR events
    """
    # the non-comment api object
    # TODO - replace with your API token
    api = requests.get(link, headers={'Authorization': 'Token <your-token-here>' } 
     
    #seek 200 response
    if api.status_code == requests.codes.ok:
        jEvents = api.json() # the api object
        getRelevantEventData(jEvents)
        
        nLink = jEvents['next'] #recursive link to next page until 'None'
        if nLink is not None: # the api will have this value set to null when it is out of pages; python sees this as 'None'
            getFirData(nLink) #start the function again for the next page
    else:
        # The link was incorrect, or we could not connect; again, this will throw an error, but
        #   a try catch block will not run for reasons unknown
        print "There was a problem connecting to %r " % (events.url)
        raise ConnectionError

#-------------------------------------------------------------------------------

#def isCellEmpty(dwst, cellStart):

# The current data is written into an archive sheets doc, with a new tab
# created, so that a trending graph can be utilized in the current sheet

def archiveData(gs, upDATE, totalThreats, mttc):
    """
    This function archives the old FIR report, so that it can be used in a 
    trending graph for the current report.
    The gspread object, with authorized credentials, is passed from the 
    exportToGsheets() method into this one. 
    """
    print "Archiving the data..."
    # TODO - your sheets name here
    gst = gs.open('Your Google Sheets Report here')
 
    # TODO if cell exists; iterate over
   
    # TODO - if your sheet is named differently than "Archive, then modify this" 
    dwst = gst.worksheet("Archive")
    
    if dwst.cell(1, 1).value is not None:
        print "A1 is taken"
    else:
        print "I dont work"
    if dwst.cell(2, 1).value is not None:
        print "I dont work"
    else:
        print "A2 is empty"
    #print dwst.row_count
    #dateCellNo = 1 # to iterate
    #dateCell = dwst.range(2, 1, 2, 1) 

#-------------------------------------------------------------------------------

# export the data into Google Sheets
# API Reference: http://gspread.readthedocs.io
def exportToGsheets(mttc):
    """
    This function exports the relevant data to the Google sheets doc
    The sheets doc has builtins which create the relevant graphs
    It utilizes the GsObject Class
    """
    gso = GsObject("https://spreadsheets.google.com/feeds") # create the parent Google Sheets object
    
    # make this a child class with the authenticated credentials
    gs = gso.authCreds()
    
    
    # the sheet needs to be shared with the client email prior to execution 
    # TODO - Put the name of your report sheet here
    gst = gs.open('Your-Gsheet-name-goes-here')
    # dwst identifies the Data worksheet; this can be done in the object class, but makes the class object far less useful 
    # TODO - if your worksheet is not called "Data, then modify this"
    dwst = gst.worksheet("Data")
    
    upDATE = datetime.today().strftime('%m-%d-%Y') #Get the current date to export when the data was last updated 
    dwst.update_acell(('E1'), str(upDATE)) #export when the data was last updated to cell E1
    # Note: cell E2 contains a builtin within the spreadsheet that is the sum total of events
    dwst.update_acell(('E3'), ("%.1f" % mttc)) # Export mean time to close to cell E3  
    #rowCtr = 2 #leaving room for headers
    
    # updating cells as block instead of individually
    # Michael showed me this block update technique and it saved 6.5s at runtime!
    # I added the aColumn, so that it could be easily archived
    
   #aCol = dwst.range(2, 1, 16, 1) #parameters(fromrow, fromcol, torow, tocol)
    bCol = dwst.range(2, 2, 16, 2) #parameters(fromrow, fromcol, torow, tocol)
    i = 0 # iterator
    totalThreats = 0
    for k, v in cDict.iteritems(): 
        #aCol[i].value = k 
        bCol[i].value = v
        totalThreats += v 
        i += 1  
 
    #dwst.update_cells(aCol) #update the entire block at once
    dwst.update_cells(bCol) #update the entire block at once
    
    print "Total Threats: %d " % (totalThreats) #verify this provides the total

    # keeping this slower method, as a reference
    """
    # update cells with key:value pairs 
    for k, v in cDict.iteritems():
        # update_cell method parameters are (row, column, value_to_insert)
        #dwst.update_cell(rowCtr, 1, str(k)) # the category labels; just comment out this line for static labels 
        dwst.update_cell(rowCtr, 2, v) # the number of events in the category
        rowCtr += 1 # jump to the next row in the next iteration of the loop
    """
    
    # archive the old data before writing over it
    archiveData(gs, upDATE, totalThreats, mttc)

#-------------------------------------------------------------------------------

# Call methods and passes the api urls into the appropriate methods  
def main():
    """
    The Main method
    """
    # The url for the incident/event API
    # TODO - update with your FIR server name
    eventLink = 'https://your-fir-server-name/api/incidents'
    # The url for the comment API, which I deployed, courtesy of helpful pull request in the FIR github page 
    commentLink = 'https://your-fir-server-name/api/comments'
    
    # Fetches the relevant event/incident data, and provides status output
    # Note: the FIR API does not differentiate between incidents and events, though the web application does.
    #   Since we are only interacting with the API, the terms 'incident' and 'event' are used interchangeably
    #   throughout this module. 
    
    print "Fetching Event Data..." 
    getFirData(eventLink)
    
    # Fetches the Close dates from the comment API     
    print "Fetching the close data from the comments..."
    getCloseDate(commentLink)
    
    # Returns the mean time to close as type 'float', formatted to the tenth decimal place
    print "Calculating the mean time to close..."
    mttc = getMttc()

    # Exports the relevant data to the spreadsheet, and passes in the mean time to close
    #   as a parameter from the 'getMttc()' method
    print "Exporting to Google Sheets..."
    exportToGsheets(mttc)
    print "Done!"
#-------------------------------------------------------------------------------

# A traditional pythonic expression that calls the main method if the name of the module
# is invoked as argument[0] from the console (firMetrics.py in this case)

# The alternative is to simply invoke the uncontained main method instructions in the module directly;
#   (i.e. outside a declared method/with no tabs). I prefer the main() method container as it reads a little 
#   easier and allows for the explicit declaration of global variables outside its parameters.

if __name__ == "__main__":
    main()

