# New design

### Application logo
- version 1 with location icon and version 2 with ghost icon.
 
<img src="https://raw.githubusercontent.com/MatejKovacic/silent-sms-ping/master/design/silent_sms_ghost.png" width=100px>
<img src="https://raw.githubusercontent.com/MatejKovacic/silent-sms-ping/master/design/silent_sms_location.png" width=100px>

### Application main screen
- history of sent and received silent SMS messages, where you can see if message has been sent or received, to or from number, time of message and result of a ping (phone has been on, off or silent SMS has been received);
- press on a history record opens a screen that shows message details; 
- search bar among these messages (search by from/to number, or date/time);
- entry field for phone number to send SMS message (you can select number from contacts or enter phine number manually).

<img src="https://raw.githubusercontent.com/MatejKovacic/silent-sms-ping/master/design/main_window_silent_sms.png" width=200px>

### Message history record
Press on a history record opens a screen that shows message details:
- arrow showing whether message is incoming or outgoing;
- if message was outgoing, what is result of a ping (red, green or blue icon);
- to or from phone number;
- date and time of the message;
- location (if recorded if not: "not enabled"; see below for more info);
- technical data about the message with complete payload and other PDU details.

### Application settings contain:
- slider to select if you want to receive silent SMS messages;
- slider to select if phone location should be logged when message is sent or received (this is saved into the history of sent and received silent SMS messages);
- slider to select if data about **received** silent SMS messages should be sent to server;
- input field for the URL of the server which is used for collecting information about received silent SMS messages;
- device ID (only shown on a screen).

<img src="https://raw.githubusercontent.com/MatejKovacic/silent-sms-ping/master/design/settings_window_silent_sms.png" width=200px>

### Notification
Notification contains:
- title: "Silent SMS detector - {time of notification}"
- text "Silent SMS has been detected! \n Received from: {number/unknown} \n Detected at {date and time}"
- "VIEW" button to open application.

### New functionality
Proposal for new functionality: data collection for threat analytics. If user agrees (and select this in settings), data about received SMSes will be sent to threat analytics server:
- device ID
- date and time of event
- number from which silent SMS has been received
- phone location (if enabled)
- PDU data (SMSC, payload,...)

User can enter URL of the threat analytic server. Data collection would be used for detecting patterns, i. e. if silent SMSes are used to track users. Typical example of use: data from journalists are collected on their own threat analytics server. 
