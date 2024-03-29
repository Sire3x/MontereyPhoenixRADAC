Author: Tyler Furches

SCHEMA Authentication

/*-----------------------
  USER BEHAVIORS
-------------------------*/

ROOT Supervisor: [(Sends_Endorsment_To_Admin|
    			  Doesnt_Send_Endorsment)]; 



/*----------------------
	USER BEHAVIORS
-----------------------*/
ROOT User: 	(Request_Access|
    
    		Malicious_Access_Request)

			
			(Accesses_File | Doesnt_Access_File) ;

/*-----------------------
  SYSTEM BEHAVIORS
-------------------------*/

ROOT System:	Check_National_Emergency_Status
				(Passes_Flat_Access_Check|Fails_Flat_Access_Check)
				Make_Risk_Assessment
				(Access_Granted|Initially_Deny)
				[System_Sends_Endorsement_Request_To_Supervisor
				Reevaluates_Risk
				( Deny_access |Grant_access|Grants_Access_With_Conditional )] ;
				

IF #Access_Granted == 1 THEN ENSURE #Reevaluates_Risk == 0;
FI;

IF #Access_Granted == 0 THEN ENSURE #Reevaluates_Risk == 1;
FI; 



/*Have risk assessment added after Endorsements Verifcation
Potentially add a supervisor or superior root that is able
to influence the Endorsement and how it calcualtes the risk
score 

Flat Access Check 
will replace the Check User clearence
and need to know block 
After flat access check assess risk 

System will ping Supervisor to say user needs a Endorsment,
The Supervisor will then send an endorsment (If they get it) 
to the administrator who will then update the risk --Potentially 
add multiple levels Of Endorsment.  Make sure endorsments 
are flagged as temporary privlegdes 
                         
Add different levels of oversight with Endorsment, can use
wired devices, can download, can print, etc. 

2nd Need to know is implied during the Endorsement following
IRA 

Some emergencies will require more or less access
depending on the emergency, may make more than just 3 
and have 2 seperate options ofr each of the 3 main 
emergencies

In emergencies the process typically implies enhancing the 
user as opposed to enhancing the system.  If your friend
needs to get in your house youre going to give them a key
not remove the door. 




Supervisor getting socially engineered by mailicious actor

*/
                



ROOT Admin: 	(Low_Emergency_Triggered |  High_Emergency_Triggered )
				[(Authenticate_Endorsment|Doesnt_Authenticate_Endorsment)];

ROOT Policy: Guidelines_for_what_constitutes_as_National_emergency
			 Guidelines_for_what_clearance_or_need_to_know_are_acceptable_in_emergency            
			 [(Guidelines_for_when_to_check_for_endorements
			 Guidelines_for_wheather_endorsment_is_sufficient_to_grant_access |
                Guidelines_for_when_to_check_for_endorements )];


/*-----------------------
  INTERACTION CONSTRAINTS
-------------------------*/
/*User access request goes from User to System*/
COORDINATE 	$a: (Request_Access|Malicious_Access_Request)	FROM User,
			$b: Check_National_Emergency_Status	FROM System
			DO ADD $a PRECEDES $b; OD;

/*Connects one of the factors from Emergency check to check it*/
COORDINATE $a: (Low_Emergency_Triggered|High_Emergency_Triggered) FROM Admin,
		   $b: Guidelines_for_what_constitutes_as_National_emergency FROM Policy
		    DO ADD $a PRECEDES $b; OD; 


/*Does the same above except for policy*/
COORDINATE $a: Guidelines_for_what_constitutes_as_National_emergency FROM Policy,
		   $b: Check_National_Emergency_Status FROM System
		   DO ADD $a PRECEDES $b; OD; 

/* Connects the System to Supervisor when check fails, meaning
it requests an endorsement*/
COORDINATE $a: System_Sends_Endorsement_Request_To_Supervisor FROM System,
		   $b: Sends_Endorsment_To_Admin FROM Supervisor 
		   DO ADD $a PRECEDES $b; OD; 

/*Sends the Supervisors endorcement to admin to verify*/

COORDINATE $a: (Sends_Endorsment_To_Admin|Doesnt_Send_Endorsment) FROM Supervisor, 
		   $b: (Authenticate_Endorsment|Doesnt_Authenticate_Endorsment) FROM Admin
		   DO ADD $a PRECEDES $b; OD;
		   

/*Connects the satisfaction req from Policy for Endorse
to the Admins AUthnetication of the endorsement*/
COORDINATE $a:  Guidelines_for_wheather_endorsment_is_sufficient_to_grant_access FROM Policy, 
		   $b: (Authenticate_Endorsment|Doesnt_Authenticate_Endorsment) FROM Admin
		   DO ADD $a PRECEDES $b; OD; 


/*Connects the admins authnetication to the access system*/

COORDINATE $a: (Authenticate_Endorsment|Doesnt_Authenticate_Endorsment) FROM Admin, 
		   $b: Reevaluates_Risk FROM System 
		   DO ADD $a PRECEDES $b; OD;
		   

/* Policy Coordinate for Make Flat Access check */
COORDINATE $a: Guidelines_for_what_clearance_or_need_to_know_are_acceptable_in_emergency FROM Policy,
		   $b: (Passes_Flat_Access_Check|Fails_Flat_Access_Check) FROM System
		   DO ADD $a PRECEDES $b; OD; 


/*Policy for Endorsments and stuff*/
COORDINATE $a: Guidelines_for_when_to_check_for_endorements FROM Policy,
		   $b: System_Sends_Endorsement_Request_To_Supervisor FROM System
		   DO ADD $a PRECEDES $b; OD; 

/* Yes dec to Yes dec  */
IF #Access_Granted > 0 THEN 
COORDINATE $a: Access_Granted FROM System, 
		   $b: Accesses_File FROM User 
		   DO ADD $a PRECEDES $b; OD;
		   FI; 

/* Second yes dec tree that incorps all event types*/
IF #System_Sends_Endorsement_Request_To_Supervisor > 0 THEN
COORDINATE $a: (Deny_access|Grant_access|Grants_Access_With_Conditional) FROM System,
		   $b: (Doesnt_Access_File|Accesses_File) FROM User
		   DO ADD $a PRECEDES $b; OD; 
		   FI; 



