rule SIGNATURE_BASE_FVEY_Shadowbroker_User_Tool_Earlyshovel
{
	meta:
		description = "Auto-generated rule - file user.tool.earlyshovel.COMMON"
		author = "Florian Roth (Nextron Systems)"
		id = "d2640f9f-8934-5095-9c30-f24941685c9e"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_fvey_shadowbroker_dec16.yar#L321-L334"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "396810b439ac53f393ad37a8acbd7236f8325730c75c1a6339e4c6343ecade7a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "504e7a376c21ffbfb375353c5451dc69a35a10d7e2a5d0358f9ce2df34edf256"

	strings:
		$x1 = "--tip 127.0.0.1 --tport 2525 --cip REDIRECTOR_IP --cport RANDOM_PORT" ascii

	condition:
		1 of them
}
