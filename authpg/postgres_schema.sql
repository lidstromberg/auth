/*********************************************************************
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
GRANT USAGE ON SCHEMA public TO therage;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO therage;

Defaults for system running
*********************************************************************/

CREATE TABLE public.systemdefault
(
    systemdefaultid bigserial NOT NULL,
    itemkey character varying(100) COLLATE pg_catalog."default" NOT NULL,
    itemvalue character varying(510) COLLATE pg_catalog."default" NOT NULL,
    createddate timestamp with time zone NOT NULL DEFAULT now(),
    lasttouched timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT pk_systemdefault PRIMARY KEY (systemdefaultid),
    CONSTRAINT uc_systemdefault_1 UNIQUE (itemkey)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.systemdefault
    OWNER to therage;

/*********************************************************************
-- Table: public.useraccount
-- DROP TABLE public.useraccount;

Main store for user accounts

*********************************************************************/
CREATE TABLE public.useraccount
(
    useraccountid character varying(50) COLLATE pg_catalog."default" NOT NULL,
    email character varying(510) COLLATE pg_catalog."default" NOT NULL,
    passwordhash text COLLATE pg_catalog."default" NOT NULL,
    emailconfirmed boolean NOT NULL,
    lockoutenabled boolean NOT NULL,
    accessfailedcount integer NOT NULL,
    lockoutend timestamp with time zone,
    phonenumber text COLLATE pg_catalog."default",
    phonenumberconfirmed boolean NOT NULL,
    twofactorenabled boolean NOT NULL,
    twofactorhash text COLLATE pg_catalog."default",
    isactive boolean NOT NULL DEFAULT true,
    islockedforedit boolean NOT NULL DEFAULT false,
    createddate timestamp with time zone NOT NULL DEFAULT now(),
    retireddate timestamp with time zone,
    lasttouched timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT pk_useraccount PRIMARY KEY (useraccountid),
    CONSTRAINT uc_useraccount_1 UNIQUE (email)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.useraccount
    OWNER to therage;
	
/*********************************************************************
-- Table: public.useraccountapplication
-- DROP TABLE public.useraccountapplication;

Stores authorisations as applicationname strings

Use dot notation if you require authorisation hierarchies.
E.g.

portal
portal.admin
portal.user

Do not use the colon character for authorisation hierarchies because
this is used for the ConstAppRoleDelim in authconst.go and sessionconst.go.

Alternatively, change the ConstAppRoleDelim to use a different character if
you require the colon delimiter in your authorisation hierarchies.

*********************************************************************/
CREATE TABLE public.useraccountapplication
(
    useraccountapplicationid bigserial NOT NULL,
    useraccountid character varying(50) COLLATE pg_catalog."default" NOT NULL,
    applicationname character varying(255) COLLATE pg_catalog."default" NOT NULL,
    isactive boolean NOT NULL DEFAULT true,
    createddate timestamp with time zone NOT NULL DEFAULT now(),
    retireddate timestamp with time zone,
    CONSTRAINT pk_useraccountapplication PRIMARY KEY (useraccountapplicationid),
    CONSTRAINT uc_useraccountapplication_1 UNIQUE (useraccountid, applicationname),
    CONSTRAINT fk_useraccountapplication_useraccount_1 FOREIGN KEY (useraccountid)
        REFERENCES public.useraccount (useraccountid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.useraccountapplication
    OWNER to therage;

	
/*********************************************************************
-- Table: public.useraccountconfirmation
-- DROP TABLE public.useraccountconfirmation;

Records activity during the registration workflow:
User registers account
Registration email is sent (useraccountconfirmation is created)
User clicks "confirm registration" link
Account is fully registered (activated date is recorded)

*********************************************************************/
CREATE TABLE public.useraccountconfirmation
(
    confirmtoken character varying(50) COLLATE pg_catalog."default" NOT NULL,
    email character varying(510) COLLATE pg_catalog."default" NOT NULL,
    useraccountid character varying(50) COLLATE pg_catalog."default" NOT NULL,
    tokenused boolean NOT NULL DEFAULT false,
    useraccountconfirmationtype character varying(50) COLLATE pg_catalog."default" NOT NULL,
    redirectlink character varying(510) COLLATE pg_catalog."default" NOT NULL,
    createddate timestamp with time zone NOT NULL DEFAULT now(),
    expirydate timestamp with time zone NOT NULL DEFAULT (now() + '24:00:00'::interval),
    activateddate timestamp with time zone,
    CONSTRAINT pk_useraccountconfirmation PRIMARY KEY (confirmtoken),
    CONSTRAINT fk_useraccountconfirmation_useraccount_1 FOREIGN KEY (useraccountid)
        REFERENCES public.useraccount (useraccountid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.useraccountconfirmation
    OWNER to therage;
	
/*********************************************************************
-- FUNCTION: public.start_useraccountconfirmation(jsonb)
-- DROP FUNCTION public.start_useraccountconfirmation(jsonb);
*********************************************************************/

CREATE OR REPLACE FUNCTION public.start_useraccountconfirmation(
	in_useraccounttoken jsonb)
    RETURNS boolean
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: start_useraccountconfirmation
Auth: DF
Date: 23.05.2018

Notes:
    Receives a useraccountconfirmation record in json format
    and saves it into the useraccountconfirmation table

*********************************************************************/
#variable_conflict use_column
DECLARE
	l_confirmtoken character varying(50);
	l_email character varying(510);
	l_useraccountid character varying(50);
	l_useraccountconfirmationtype character varying(50);
	l_redirectlink character varying(510);
BEGIN
	--collect data for sanity checks
	select
		nullif(uac1.confirmtoken,''),
		nullif(uac1.email,''),
		nullif(uac1.useraccountid,''),
		nullif(uac1.useraccountconfirmationtype,''),
		nullif(uac1.redirectlink,'')
	into
		l_confirmtoken,
		l_email,
		l_useraccountid,
		l_useraccountconfirmationtype,
		l_redirectlink
	from jsonb_to_record(in_useraccounttoken)
	as uac1(
		confirmtoken character varying(50), 
		email character varying(510), 
		useraccountid character varying(50), 
		tokenused boolean, 
		useraccountconfirmationtype character varying(50), 
		redirectlink character varying(510), 
		createddate timestamp with time zone, 
		expirydate timestamp with time zone, 
		activateddate timestamp with time zone
	);
	
	--check confirm token
	if l_confirmtoken is null then
		raise exception 'Confirmation token is missing'
		using hint = 'Please supply the confirmation token';
	end if;
	
	--check email
	if l_email is null then
		raise exception 'Email is missing'
		using hint = 'Please supply the email for this account';
	end if;
	
	--check user account is present
	if l_useraccountid is null then
		raise exception 'User account is missing'
		using hint = 'Please supply the user account';
	end if;
	
	--check confirm type is present and valid
	if l_useraccountconfirmationtype is null or (l_useraccountconfirmationtype not in ('registration', 'credentialreset')) then
		raise exception 'Confirmation type is missing or invalid'
		using hint = 'Please supply a valid confirmation type';
	end if;
	
	--check redirect link is present
	if l_redirectlink is null then
		raise exception 'Redirect link is missing'
		using hint = 'Please supply the redirect link';
	end if;
	
	--check that the token hasn't been used before for another account
	if exists (
		select 1
		from public.useraccountconfirmation acc1
		where acc1.confirmtoken=l_confirmtoken
		and acc1.email=l_email
	) then
		raise exception 'Confirm token cannot be used'
		using hint = 'Please generate a new confirm token';
	end if;

-- load in the user account
	insert into public.useraccountconfirmation
	(
		confirmtoken,
		email,
		useraccountid,
		tokenused,
		useraccountconfirmationtype,
		redirectlink,
		createddate,
		expirydate
	)
	select
		uac1.confirmtoken,
		uac1.email,
		uac1.useraccountid,
		coalesce(uac1.tokenused,false),
		uac1.useraccountconfirmationtype,
		uac1.redirectlink,
		coalesce(uac1.createddate,now()),
		coalesce(uac1.expirydate,now() + '24:00:00'::interval)
	from jsonb_to_record(in_useraccounttoken)
	as uac1(
		confirmtoken character varying(50), 
		email character varying(510), 
		useraccountid character varying(50), 
		tokenused boolean, 
		useraccountconfirmationtype character varying(50), 
		redirectlink character varying(510), 
		createddate timestamp with time zone, 
		expirydate timestamp with time zone, 
		activateddate timestamp with time zone
	)
	on conflict (confirmtoken) do update set
		tokenused=EXCLUDED.tokenused,
		redirectlink=EXCLUDED.redirectlink,
		expirydate=EXCLUDED.expirydate;

return true;
END

$BODY$;

ALTER FUNCTION public.start_useraccountconfirmation(jsonb)
    OWNER TO therage;



CREATE OR REPLACE FUNCTION public.get_useraccountconfirmation(
	in_useraccounttoken character varying(50))
    RETURNS jsonb
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$

/*********************************************************************
Name: get_useraccountconfirmation
Auth: DF
Date: 23.05.2018

Notes:
    Returns a confirmation record

*********************************************************************/
#variable_conflict use_column
DECLARE
	l_jsonresult jsonb;
BEGIN

	select row_to_json(uac)
	into l_jsonresult
	from
	(
		select
			uac1.confirmtoken,
			uac1.email,
			uac1.useraccountid,
			uac1.tokenused,
			uac1.useraccountconfirmationtype,
			uac1.redirectlink,
			uac1.createddate,
			uac1.expirydate,
			uac1.activateddate
		from public.useraccountconfirmation uac1
		where uac1.confirmtoken=in_useraccounttoken
	) uac;	

	return l_jsonresult;
END

$BODY$;

ALTER FUNCTION public.get_useraccountconfirmation(character varying)
    OWNER TO therage;

-- FUNCTION: public.finish_useraccountconfirmation(character varying)
-- DROP FUNCTION public.finish_useraccountconfirmation(character varying);

CREATE OR REPLACE FUNCTION public.finish_useraccountconfirmation(
	in_useraccounttoken character varying(50))
    RETURNS jsonb
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: finish_useraccountconfirmation
Auth: DF
Date: 23.05.2018

Notes:
    Completes the user registration process by receiving the 
    confirmation token

*********************************************************************/
DECLARE
	l_tokenExists int;
	l_tokenexpired boolean;
	l_useraccountconfirmationtype character varying(50);
	l_redirectlink character varying(510);
	l_jsonresult jsonb;
BEGIN
	select 
		count(1), 
		ac1.useraccountconfirmationtype, 
		ac1.redirectlink
	into 
		l_tokenExists, 
		l_useraccountconfirmationtype, 
		l_redirectlink
	from public.useraccountconfirmation ac1
	where ac1.confirmtoken=in_useraccounttoken
	and ac1.expirydate>=now()
	and ac1.tokenused=false
	group by ac1.useraccountconfirmationtype, ac1.redirectlink;

	if l_tokenExists>0 then
	--mark as used
		update public.useraccountconfirmation ac1 set
			tokenused=true,
			activateddate=now()
		where ac1.confirmtoken=in_useraccounttoken
		and ac1.tokenused=false;
		
		if l_useraccountconfirmationtype='registration' then
		--mark as confirmed
			update public.useraccount ua1 set
				emailconfirmed=true,
				lasttouched=now()
			from public.useraccountconfirmation ac1
			where ac1.email=ua1.email
			and ac1.confirmtoken=in_useraccounttoken;
		end if;
	end if;

	--return json result
	select row_to_json(cnf)
	into l_jsonresult
	from
	(
		select 
			case when l_tokenExists>0 then true else false end as result, 
			l_useraccountconfirmationtype as useraccountconfirmationtype,
			l_redirectlink as redirectlink
	) cnf;
	
	return l_jsonresult;
END

$BODY$;

ALTER FUNCTION public.finish_useraccountconfirmation(character varying)
    OWNER TO therage;


-- FUNCTION: public.get_useraccountcredential(character varying)
-- DROP FUNCTION public.get_useraccountcredential(character varying);

CREATE OR REPLACE FUNCTION public.get_useraccountcredential(
	in_email character varying(510))
    RETURNS jsonb
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE
AS $BODY$
/*********************************************************************
Name: get_useraccountcredential
Auth: DF
Date: 23.05.2018

Notes:
    Returns the user account id and password hash
    (for login checks)

*********************************************************************/
DECLARE
	l_jsonresult jsonb;
BEGIN
	select row_to_json(crd)
	into l_jsonresult
	from
	(
		select 
			ua1.useraccountid, 
			ua1.passwordhash,
			ua1.twofactorenabled,
			ua1.twofactorhash,
			ua1.lockoutenabled,
			ua1.accessfailedcount,
			ua1.lockoutend
		from public.useraccount ua1
		where ua1.email=in_email
	) crd;
	
	return l_jsonresult;
END

$BODY$;

ALTER FUNCTION public.get_useraccountcredential(character varying)
    OWNER TO therage;


-- FUNCTION: public.set_useraccountcredential(character varying, text)
-- DROP FUNCTION public.set_useraccountcredential(character varying, text);

CREATE OR REPLACE FUNCTION public.set_useraccountcredential(
	in_useraccountid character varying(50),
	in_passwordhash text)
    RETURNS boolean
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: set_useraccountcredential
Auth: DF
Date: 23.05.2018

Notes:
    Sets a new password for a given account

*********************************************************************/
BEGIN
	update public.useraccount set
		passwordhash=in_passwordhash
	where useraccountid=in_useraccountid;
	
	return true;
END

$BODY$;

ALTER FUNCTION public.set_useraccountcredential(character varying, text)
    OWNER TO therage;

-- FUNCTION: public.get_useraccount(character varying)
-- DROP FUNCTION public.get_useraccount(character varying);

CREATE OR REPLACE FUNCTION public.get_useraccount(
	in_useraccountid character varying(50))
    RETURNS jsonb
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: get_useraccount
Auth: DF
Date: 23.05.2018

Notes:
    Returns a useraccount record in json format

*********************************************************************/
DECLARE
	l_jsonResult jsonb;
BEGIN
	select row_to_json(ua1)
	into l_jsonResult
	from
	(
		select
			uac1.useraccountid,
			uac1.email,
			uac1.passwordhash,
			uac1.emailconfirmed,
			uac1.lockoutenabled,
			uac1.accessfailedcount,
			uac1.lockoutend,
			uac1.phonenumber,
			uac1.phonenumberconfirmed,
			uac1.twofactorenabled,
			uac1.twofactorhash,
			uac1.isactive,
			uac1.islockedforedit,
			(
				select array_to_json(array_agg(row_to_json(uap1)))
				from
				(
					select
						uap1.applicationname,
						uap1.isactive,
						uap1.createddate,
						uap1.retireddate
					from public.useraccountapplication uap1
					where uap1.useraccountid=uac1.useraccountid
				) uap1
			) scopes,
			public.get_sanitiseddate(uac1.createddate) as createddate,
			public.get_sanitiseddate(uac1.retireddate) as retireddate,
			public.get_sanitiseddate(uac1.lasttouched) as lasttouched
		from public.useraccount uac1
		where uac1.useraccountid=in_useraccountid
	) ua1;
	
	return 
		l_jsonResult;
END

$BODY$;

ALTER FUNCTION public.get_useraccount(character varying)
    OWNER TO therage;


-- FUNCTION: public.get_useraccountbyemail(character varying)
-- DROP FUNCTION public.get_useraccountbyemail(character varying);

CREATE OR REPLACE FUNCTION public.get_useraccountbyemail(
	in_email character varying(510))
    RETURNS jsonb
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: get_useraccountbyemail
Auth: DF
Date: 23.05.2018

Notes:
    Returns a useraccount record in json format

*********************************************************************/
DECLARE
	l_jsonResult jsonb;
BEGIN
	select row_to_json(ua1)
	into l_jsonResult
	from
	(
		select
			uac1.useraccountid,
			uac1.email,
			uac1.passwordhash,
			uac1.emailconfirmed,
			uac1.lockoutenabled,
			uac1.accessfailedcount,
			uac1.lockoutend,
			uac1.phonenumber,
			uac1.phonenumberconfirmed,
			uac1.twofactorenabled,
			uac1.twofactorhash,
			uac1.isactive,
			uac1.islockedforedit,
			(
				select array_to_json(array_agg(row_to_json(uap1)))
				from
				(
					select
						uap1.applicationname,
						uap1.isactive,
						uap1.createddate,
						uap1.retireddate
					from public.useraccountapplication uap1
					where uap1.useraccountid=uac1.useraccountid
				) uap1
			) scopes,
			public.get_sanitiseddate(uac1.createddate) as createddate,
			public.get_sanitiseddate(uac1.retireddate) as retireddate,
			public.get_sanitiseddate(uac1.lasttouched) as lasttouched
		from public.useraccount uac1
		where uac1.email=in_email
	) ua1;
	
	return 
		l_jsonResult;
END

$BODY$;

ALTER FUNCTION public.get_useraccountbyemail(character varying)
    OWNER TO therage;


-- FUNCTION: public.set_useraccount(jsonb)
-- DROP FUNCTION public.set_useraccount(jsonb);

CREATE OR REPLACE FUNCTION public.set_useraccount(
	in_useraccount jsonb)
    RETURNS character varying(50)
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: set_useraccount
Auth: DF
Date: 23.05.2018

Notes:
    Receives a useraccount in json format and saves it to the 
    useraccount table

*********************************************************************/
#variable_conflict use_column
DECLARE
	l_useraccountid character varying(50);
	l_email character varying(510);
	l_passwordhash text;
BEGIN
	select
		nullif(uac1.useraccountid,''),
		nullif(uac1.email,''),
		nullif(uac1.passwordhash,'')
	into
		l_useraccountid,
		l_email,
		l_passwordhash
	from jsonb_to_record(in_useraccount)
	as uac1(
		useraccountid character varying(50), 
		email character varying(510), 
		passwordhash text, 
		emailconfirmed boolean, 
		lockoutenabled boolean, 
		accessfailedcount integer, 
		lockoutend timestamp with time zone, 
		phonenumber text, 
		phonenumberconfirmed boolean, 
		twofactorenabled boolean,
		twofactorhash text,
		isactive boolean, 
		islockedforedit boolean,
		scopes text,
		createddate timestamp with time zone, 
		retireddate timestamp with time zone, 
		lasttouched timestamp with time zone
	);
	
	--check for email
	if l_email is null then
		raise exception 'Email is missing'
		using hint = 'Please supply the email address';
	end if;
	
	--check for the password
	if l_passwordhash is null then
		raise exception 'Password is missing'
		using hint = 'Please supply the password';
	end if;
	
	--attempt to find the account 
	if l_useraccountid is null and exists (
		select 1
		from public.useraccount uac1
		where uac1.email=l_email
	) then
		raise exception 'Account already exists'
		using hint = 'Please login';
	end if;

-- load in the user account
	insert into public.useraccount
	(
		useraccountid,
		email,
		passwordhash,
		emailconfirmed,
		lockoutenabled,
		accessfailedcount,
		lockoutend,
		phonenumber,
		phonenumberconfirmed,
		twofactorenabled,
		twofactorhash,
		isactive,
		islockedforedit,
		createddate,
		lasttouched
	)
	select
		case when uac1.useraccountid='' then replace(cast(uuid_generate_v4() as varchar(50)),'-','') else uac1.useraccountid end,
		uac1.email,
		uac1.passwordhash,
		coalesce(uac1.emailconfirmed,false),
		coalesce(uac1.lockoutenabled,true),
		coalesce(uac1.accessfailedcount,0),
		uac1.lockoutend,
		nullif(uac1.phonenumber,''),
		coalesce(uac1.phonenumberconfirmed,false),
		coalesce(uac1.twofactorenabled,false),
		nullif(uac1.twofactorhash,''),
		coalesce(uac1.isactive,true),
		coalesce(uac1.islockedforedit,false),
		coalesce(public.get_sanitiseddate(uac1.createddate),now()),
		coalesce(public.get_sanitiseddate(uac1.lasttouched),now())
	from jsonb_to_record(in_useraccount)
	as uac1(
		useraccountid character varying(50), 
		email character varying(510), 
		passwordhash text, 
		emailconfirmed boolean, 
		lockoutenabled boolean, 
		accessfailedcount integer, 
		lockoutend timestamp with time zone, 
		phonenumber text, 
		phonenumberconfirmed boolean, 
		twofactorenabled boolean,
		twofactorhash text,
		isactive boolean, 
		islockedforedit boolean,  
		scopes text,
		createddate timestamp with time zone, 
		lasttouched timestamp with time zone
	)
	on conflict (useraccountid) do update set
		accessfailedcount=EXCLUDED.accessfailedcount,
		email=EXCLUDED.email,
		emailconfirmed=EXCLUDED.emailconfirmed,
		lockoutenabled=EXCLUDED.lockoutenabled,
		lockoutend=EXCLUDED.lockoutend,
		passwordhash=case when EXCLUDED.passwordhash!='pwd' then EXCLUDED.passwordhash else public.useraccount.passwordhash end,
		phonenumber=EXCLUDED.phonenumber,
		phonenumberconfirmed=EXCLUDED.phonenumberconfirmed,
		twofactorenabled=EXCLUDED.twofactorenabled,
		twofactorhash=EXCLUDED.twofactorhash,
		isactive=EXCLUDED.isactive,
		islockedforedit=EXCLUDED.islockedforedit,
		retireddate=EXCLUDED.retireddate,
		lasttouched=now()
	returning useraccountid into l_useraccountid;
	
	insert into public.useraccountapplication
	(
		useraccountid,
		applicationname,
		isactive,
		createddate,
		retireddate
	)
	select distinct
		l_useraccountid,
		uac2.applicationname,
		coalesce(uac2.isactive,true),
		coalesce(public.get_sanitiseddate(uac2.createddate),now()),
		public.get_sanitiseddate(uac2.retireddate)
	from jsonb_to_record(in_useraccount)
	as uac1(
		useraccountid character varying(50), 
		email character varying(510), 
		passwordhash text, 
		emailconfirmed boolean, 
		lockoutenabled boolean, 
		accessfailedcount integer, 
		lockoutend timestamp with time zone, 
		phonenumber text, 
		phonenumberconfirmed boolean, 
		twofactorenabled boolean,
		twofactorhash text,
		isactive boolean, 
		islockedforedit boolean,  
		scopes jsonb,
		createddate timestamp with time zone, 
		lasttouched timestamp with time zone
	), jsonb_to_recordset(uac1.scopes)
	as uac2(
		applicationname character varying(255),
		isactive boolean,  
		createddate timestamp with time zone,
		retireddate timestamp with time zone
	)
	on conflict (useraccountid,applicationname) do update set
		isactive=EXCLUDED.isactive,
		retireddate=EXCLUDED.retireddate;

	return l_useraccountid;
END

$BODY$;

ALTER FUNCTION public.set_useraccount(jsonb)
    OWNER TO therage;


-- FUNCTION: public.get_sanitiseddate(timestamp with time zone)
-- DROP FUNCTION public.get_sanitiseddate(timestamp with time zone);

CREATE OR REPLACE FUNCTION public.get_sanitiseddate(
	in_date timestamp with time zone)
    RETURNS timestamp with time zone
    LANGUAGE 'sql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: get_sanitiseddate
Auth: DF
Date: 23.05.2018

Notes:
    Prevents golang zero Time being returned from sql

*********************************************************************/
	select 
		case when date_part('year', in_date) > 2000 then in_date end;

$BODY$;

ALTER FUNCTION public.get_sanitiseddate(timestamp with time zone)
    OWNER TO therage;


CREATE OR REPLACE FUNCTION public.get_systemdefault(
	in_itemkey character varying(100))
    RETURNS jsonb
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: get_systemdefault
Auth: DF
Date: 23.05.2018

Notes:
    Gets the system defaults.

*********************************************************************/
DECLARE
	l_json jsonb;
BEGIN

	select row_to_json(sd)
	into l_json
	from
	(
		select 
			sd1.itemkey,
			sd1.itemvalue
		from public.systemdefault sd1
		where sd1.itemkey=in_itemkey
	) sd;
	
	return l_json;
END

$BODY$;


CREATE OR REPLACE FUNCTION public.set_systemdefault(
	in_itemkey character varying(100),
	in_itemval character varying(510)
)
    RETURNS bool
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: set_systemdefault
Auth: DF
Date: 23.05.2018

Notes:
    Sets the system defaults.

*********************************************************************/
BEGIN

	if exists (
		select 1
		from public.systemdefault sd1
		where sd1.itemkey=in_itemkey
	) then
		update public.systemdefault set
			itemvalue=in_itemval
		where itemkey=in_itemkey;
	else
		insert into public.systemdefault(itemkey,itemvalue)
		values (in_itemkey,in_itemval);
	end if;
	
	return true;
END

$BODY$;

-- FUNCTION: public.reset_failedloginattempt(character varying)
-- DROP FUNCTION public.reset_failedloginattempt(character varying);

CREATE OR REPLACE FUNCTION public.reset_failedloginattempt(
	in_email character varying(510))
    RETURNS boolean
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: reset_failedloginattempt
Auth: DF
Date: 29.07.2018

Notes:
    Updates the user table when a login attempt has failed

*********************************************************************/
#variable_conflict use_column
BEGIN
	update public.useraccount as uac1 set
		lockoutend=now(),
		accessfailedcount=0
	where uac1.email=in_email;

	return true;
END

$BODY$;

ALTER FUNCTION public.reset_failedloginattempt(character varying)
    OWNER TO therage;
	
-- FUNCTION: public.set_failedloginattempt(character varying)
-- DROP FUNCTION public.set_failedloginattempt(character varying);


CREATE OR REPLACE FUNCTION public.set_failedloginattempt(
	in_email character varying(510))
    RETURNS boolean
    LANGUAGE 'plpgsql'

    COST 100
    VOLATILE 
AS $BODY$
/*********************************************************************
Name: set_failedloginattempt
Auth: DF
Date: 29.07.2018

Notes:
    Updates the user table when a login attempt has failed

*********************************************************************/
#variable_conflict use_column
BEGIN
	if exists (
		select 1
		from public.useraccount uac1
		where uac1.email=in_email
		and uac1.accessfailedcount>2
	) then
		update public.useraccount as uac1 set
			accessfailedcount=uac1.accessfailedcount + 1,
			lockoutend=now() + INTERVAL '15 minutes'
		where uac1.email=in_email;
		
		return true;
	end if;
	
	update public.useraccount as uac1 set
		accessfailedcount=uac1.accessfailedcount + 1
	where uac1.email=in_email;
	
	return false;
END

$BODY$;

ALTER FUNCTION public.set_failedloginattempt(character varying)
    OWNER TO therage;
