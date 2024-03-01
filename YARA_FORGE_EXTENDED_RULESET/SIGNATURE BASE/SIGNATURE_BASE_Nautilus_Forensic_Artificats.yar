rule SIGNATURE_BASE_Nautilus_Forensic_Artificats
{
	meta:
		description = "Rule for detection of Nautilus related strings"
		author = "NCSC UK / Florian Roth"
		id = "0c0a24da-4dbc-543a-9ec0-a5b1ec75c889"
		date = "2017-11-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_turla_neuron.yar#L98-L125"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "17ae559a4640636f1285c7078a4366954d5a41c098419db32315e354f0ae619d"
		score = 60
		quality = 85
		tags = ""

	strings:
		$ = "App_Web_juvjerf3.dll" fullword ascii
		$ = "App_Web_vcplrg8q.dll" fullword ascii
		$ = "ar_all2.txt" fullword ascii
		$ = "ar_sa.txt" fullword ascii
		$ = "Convert.FromBase64String(temp[1])" fullword ascii
		$ = "D68gq#5p0(3Ndsk!" fullword ascii
		$ = "dcomnetsrv" fullword ascii
		$ = "ERRORF~1.ASP" fullword ascii
		$ = "intelliAdminRpc" fullword ascii
		$ = "J8fs4F4rnP7nFl#f" fullword ascii
		$ = "Msnb.exe" fullword ascii
		$ = "nautilus-service.dll"
		$ = "Neuron_service" fullword ascii
		$ = "owa_ar2.bat" fullword ascii
		$ = "payload.x64.dll.system" fullword ascii
		$ = "service.x64.dll.system" fullword ascii

	condition:
		1 of them
}
