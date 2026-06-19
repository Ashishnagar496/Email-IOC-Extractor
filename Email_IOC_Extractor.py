import os 
import re
from email import policy
from email.parser import BytesParser
from email import * 
import tkinter as tk 
from tkinter import filedialog
#window 
window=tk.Tk()
window.geometry("1000x1000")
window.title("Email IOC Extractor")

#label 1 
label1 = tk.Label(window , text="Upload Email Files ( .eml )" ,fg="white",bg="black",font=("arial" , 18))
label1.pack(pady=20)


# file upload function  

def upload_file():
    file_path=filedialog.askopenfilename()
    file_name=os.path.basename(file_path)
    file_extension=os.path.splitext(file_name)[1]

    #file information label 
    if file_path:
        label2.config(text=f"File Name --> {file_name}",font=("arial",14))
        label3.config(text=f"Extension --> {file_extension}",font=("arial",14))


    #checking fiel extension 
        
    if ((file_extension) in (".eml",".txt")):
        label4.config(text=f"Status - Uploaded Successfully")

        #opening file for preview 
        with open(file_path , "r") as file:

            # file parsing
            phishing_words = {
    "urgency": ["immediately", "urgent", "asap", "within 24 hours", "before end of day", "act now", "don't delay", "time-sensitive", "expires today", "final notice", "account termination", "suspension pending", "last chance", "hurry", "breaking news", "flagged for review"],
    "authority": ["security alert", "account verification", "compliance department", "fraud prevention", "legal notice", "regulatory update", "authentication required", "official notice", "IT desk", "helpdesk", "secure message", "encrypted document", "signed certificate", "corporate policy", "board resolution", "executive order"],
    "fear": ["suspended", "deactivated", "blocked", "locked", "restricted", "terminated", "closed", "forfeit", "penalty", "fine", "charged", "overdraft", "collection agency", "credit damage", "insurance lapse", "benefits expired", "access revoked", "data breach", "compromised", "infected", "virus detected"],
    "greed": ["free", "complimentary", "discount", "refund", "cashback", "winner", "prize", "sweepstakes", "bonus", "reward", "gift card", "unclaimed funds", "inheritance", "winfall", "lucky draw", "limited offer", "exclusive access", "member only", "pre-approved", "vip treatment"],
    "social": ["many users", "recommended", "trusted", "top rated", "verified", "approved", "endorsed", "popular", "trending", "testimonial", "success story", "colleague", "team", "department", "headquarters", "affiliate", "partner", "sponsor", "certified"],
    "technical": ["firewall", "vpn", "two-factor", "otp", "ssl", "tls", "encryption", "decryption", "hash", "token", "certificate", "private key", "public key", "dns", "dhcp", "ip blacklist", "whitelist", "spam filter", "malware scan", "endpoint", "patch", "update", "dpi", "gdpr", "pci compliant"],
    "action_verbs": ["click", "download", "open", "view", "confirm", "verify", "update", "reset", "reactivate", "unlock", "secure", "validate", "authenticate", "reauthorize", "approve", "decline", "respond", "forward", "share", "submit", "accept", "acknowledge"]
}
            raw_email = file.read()
            msg = message_from_string(raw_email)
            # Inside your upload_file() function, after reading raw_email:
            msg = BytesParser(policy=policy.default).parsebytes(raw_email.encode('utf-8'))

            # Check if the body is base64-encoded
            body = ""
            if msg.is_multipart():
                for part in msg.iter_parts():
                    if part.get_content_type() == "text/html":
                        encoding = part.get('Content-Transfer-Encoding', '')
                        payload = part.get_payload(decode=True)  # This auto-decodes base64
                        body = payload.decode('utf-8', errors='ignore')
                        break
            else:
                encoding = msg.get('Content-Transfer-Encoding', '')
                payload = msg.get_payload(decode=True)
                body = payload.decode('utf-8', errors='ignore')

            # Now search for URLs in the decoded body
            url_pattern = r'https?://[^\s"<>]+'
            urls = re.findall(url_pattern, body)
          


            header_text = f"""
-----------------------------------------
    IMPORTANT HEADERS
-----------------------------------------

Subject     : {msg.get('Subject', 'N/A')}
From        : {msg.get('From', 'N/A')}
To          : {msg.get('To', 'N/A')}
Date        : {msg.get('Date', 'N/A')}
Reply-To    : {msg.get('Reply-To', 'N/A')}
Return-Path : {msg.get('Return-Path', 'N/A')}
Message-ID  : {msg.get('Message-ID', 'N/A')}
X-Originating-IP  : {msg.get('X-Originating-IP', 'N/A')}
X-Sender-IP  : {msg.get('X-Sender-IP', 'N/A')}
Authentication-Results : {msg.get('Authentication-Results','N/A')}
"""
            #converting email text into lower case for matching 
            msg_lower_text=body.lower()


            #storing matching words in a list 
            phish_words = []
            for trigger , words in phishing_words.items() :
                for word in words:
                    if word in msg_lower_text:
                        phish_words.append({
                            "Trigger": trigger,
                            "Indicator": word
                        })
            file.seek(0)       
            lines=[]
            for i in range(0,4):
                lines.append(file.readline())
            preview = "".join(lines)
            
            label5.config(text=f"---- Preview ----\t\n\n {preview} \n ----", justify="left")
        
        # generating report 

        with open("analysis_report.txt", "w", encoding="utf-8") as file:
            file.write(header_text)
            file.write("\n\n")
            file.write("===================")
            file.write("PHISHING INDICATORS")
            file.write("===================\n")
            for item in phish_words:
                file.write(
                f"[{item['Trigger'].upper()}] {item['Indicator']}\n" )
            file.write("\n===================URL===================\n\n")
            
            for url in urls:
                file.write(url + "\n")
            
            label6.config(text="Report Successfully Created")
                
    else :
         label4.config(text=f"Status - Extension Not Allowed")

    
# file upload button 

upload_button=tk.Button(window , text="upload",command=upload_file,width=20,height=2)
upload_button.pack(pady=3)


# file upload dynamic label    ( filename and extension )    
label2 = tk.Label(window , text="No File Selected" , fg="white" , bg="black" , font=("arial" , 14))
label2.pack(pady=3)
label3 = tk.Label(window , text="" , fg="white" , bg="black" , font=("arial" , 14))
label3.pack(pady=1)
label4 = tk.Label(window , text="" , fg="white" , bg="black" , font=("arial" , 14))
label4.pack(pady=1)
label5 = tk.Label(window , text="" , fg="white" , bg="black" , font=("arial" , 14))
label5.pack(pady=10)
label6 = tk.Label(window , text="" , fg="white" , bg="black" , font=("arial" , 14))
label6.pack(pady=10)

window.configure(background="black")
window.mainloop()

