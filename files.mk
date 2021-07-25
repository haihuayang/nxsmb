
TARGET_SET_idl := \
	misc \
	security \
	lsa \
	samr \
	netlogon \
	krb5pac \
	ntlmssp \
	dcerpc \
	svcctl \
	srvsvc \
	wkssvc \
	dssetup \
	xattr \

a=\
	mytest_x_elem_size \
	mytest_size_is \
	mytest_length_is \
	mytest_x_length \

a=\

a=\
	security \
	misc \
	netlogon \
	epmapper \
	atsvc \
	audiosrv \
	krb5pac \
	auth \
	backupkey \
	fscc \
	bkupblobs \
	srvsvc \
	browser \
	winreg \
	clusapi \
	dbgidl \
	dfsblobs \
	dfs \
	dnsp \
	dns \
	dnsserver \
	dsbackup \
	echo \
	efs \
	eventlog6 \
	eventlog \
	file_id \
	frsapi \
	frsrpc \
	frsblobs \
	fsrvp \
	fsrvp_state \
	idmap \
	initshutdown \
	ioctl \
	keysvc \
	mdssvc \
	server_id \
	messaging \
	mgmt \
	msgsvc \
	named_pipe_auth \
	nbt \
	nfs4acl \
	notify \
	ntsvcs \
	orpc \
	oxidresolver \
	policyagent \
	preg \
	printcap \
	rap \
	remact \
	rot \
	scerpc \
	schannel \
	smb2_lease_struct \
	smb_acl \
	trkwks \
	unixinfo \
	w32time \
	winbind \
	wkssvc \
	wmi \
	wzcsvc \
	xattr \

a=\
	dcom \
	drsuapi \
	drsblobs \
	frstrans \
	ntprinting \
	spoolss \
	witness \

SET_SRC_hx509 := \
	ca \
	cert \
	cms \
	collector \
	crypto \
	env \
	error \
	file \
	keyset \
	ks_dir \
	ks_file \
	ks_keychain \
	ks_mem \
	ks_null \
	ks_p11 \
	ks_p12 \
	lock \
	name \
	peer \
	print \
	req \
	revoke \
	sel \
	sel-gram \
	sel-lex \

a=\
	lex.yy \

SET_SRC_krb5 := \
	acache \
	add_et_list \
	addr_families \
	aname_to_localname \
	appdefault \
	asn1_glue \
	auth_context \
	build_ap_req \
	build_auth \
	cache \
	changepw \
	codec \
	config_file \
	constants \
	context \
	convert_creds \
	copy_host_realm \
	crc \
	creds \
	crypto-aes \
	crypto-algs \
	crypto-arcfour \
	crypto \
	crypto-des3 \
	crypto-des \
	crypto-des-common \
	crypto-evp \
	crypto-null \
	crypto-pk \
	crypto-rand \
	data \
	eai_to_heim_errno \
	error_string \
	expand_hostname \
	expand_path \
	fcache \
	free \
	free_host_realm \
	generate_seq_number \
	generate_subkey \
	get_addrs \
	get_cred \
	get_default_principal \
	get_default_realm \
	get_for_creds \
	get_host_realm \
	get_in_tkt \
	get_port \
	init_creds \
	init_creds_pw \
	kcm \
	keyblock \
	keytab_any \
	keytab \
	keytab_file \
	keytab_keyfile \
	keytab_memory \
	krbhst \
	kuserok \
	log \
	mcache \
	misc \
	mit_glue \
	mk_error \
	mk_priv \
	mk_rep \
	mk_req \
	mk_req_ext \
	n-fold \
	pac \
	padata \
	pcache \
	pkinit \
	plugin \
	principal \
	prog_setup \
	prompter_posix \
	rd_cred \
	rd_error \
	rd_priv \
	rd_rep \
	rd_req \
	replay \
	salt-aes \
	salt-arcfour \
	salt \
	salt-des3 \
	salt-des \
	send_to_kdc \
	set_default_realm \
	store \
	store_emem \
	store_fd \
	store-int \
	store_mem \
	ticket \
	time \
	transited \
	warn \

SET_SRC_roken := \
	base64 \
	bswap \
	cloexec \
	copyhostent \
	ct \
	dumpdata \
	ecalloc \
	emalloc \
	erealloc \
	estrdup \
	freeaddrinfo \
	freehostent \
	gai_strerror \
	getaddrinfo \
	getarg \
	getdtablesize \
	getipnodebyaddr \
	getipnodebyname \
	get_window_size \
	h_errno \
	hex \
	hostent_find_fqdn \
	issuid \
	net_read \
	net_write \
	parse_time \
	parse_units \
	rand \
	roken_gethostby \
	rtbl \
	signal \
	socket \
	strcollect \
	strlwr \
	strpool \
	strsep \
	strsep_copy \
	strupr \
	vis \
	xfree

SET_SRC_gssapi_krb5 := \
	copy_ccache \
	delete_sec_context \
	init_sec_context \
	context_time \
	init \
	address_to_krb5addr \
	get_mic \
	inquire_context \
	add_cred \
	inquire_cred \
	inquire_cred_by_oid \
	inquire_cred_by_mech \
	inquire_mechs_for_name \
	inquire_names_for_mech \
	indicate_mechs \
	inquire_sec_context_by_oid \
	export_sec_context \
	import_sec_context \
	duplicate_name \
	import_name \
	compare_name \
	export_name \
	canonicalize_name \
	unwrap \
	wrap \
	release_name \
	cfx \
	8003 \
	arcfour \
	encapsulate \
	display_name \
	sequence \
	display_status \
	release_buffer \
	external \
	compat \
	creds \
	acquire_cred \
	release_cred \
	store_cred \
	set_cred_option \
	decapsulate \
	verify_mic \
	accept_sec_context \
	set_sec_context_option \
	process_context_token \
	prf \
	aeap \
	pname_to_uid \
	authorize_localname \

SET_SRC_com_err := \
	com_err \
	error \

