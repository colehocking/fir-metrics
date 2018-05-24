```text
       ______________ 
      / ____/  _/ __ \
     / /_   / // /_/ /
    / __/ _/ // _, _/ 
   /_/   /___/_/ |_|  

   _____                      _ __       
  / ___/___  _______  _______(_) /___  __
  \__ \/ _ \/ ___/ / / / ___/ / __/ / / /
 ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ / 
/____/\___/\___/\__,_/_/  /_/\__/\__, /  
                                /____/
    __  ___     __       _          
   /  |/  /__  / /______(_)_________
  / /|_/ / _ \/ __/ ___/ / ___/ ___/
 / /  / /  __/ /_/ /  / / /__(__  ) 
/_/  /_/\___/\__/_/  /_/\___/____/  
                                    
```


Pulls Event Data from FIR and creates a rolling 90 day report in Google Sheets.

### FIR Prerequisites: 

- You will need a fork of FIR that has a comment API integration  
- You will also need a "closed" comment category, as the program uses this to determine the Mean Time to Close  
- You can use my fork of FIR with comment API integration [here](https://github.com/colehocking/FIR)  
- Once this data is in Google sheets; all sorts of fun graphs/charts can be created.   

### Installation: 
- Clone the repo and `cd` into it.
- Run `sudo pip install -r requirements.txt` 
    - (_Note: Disable the flag for the pandas package in "requirements.txt" if you run into any wheel issues_)
- You will need the Google Sheets API
    - If you need help setting up the Google Sheets API, refer to [this article](https://www.twilio.com/blog/2017/02/an-easy-way-to-read-and-write-to-a-google-spreadsheet-in-python.html).

- Update firMetrics.py with the necessary URL paths and tokens.  

### Usage:

- Run: `python firMetrics.py`

### TODOs:
    - archive data to create trend graph
