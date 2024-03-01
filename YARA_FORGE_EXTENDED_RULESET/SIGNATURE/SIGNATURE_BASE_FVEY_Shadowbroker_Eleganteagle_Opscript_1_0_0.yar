rule SIGNATURE_BASE_FVEY_Shadowbroker_Eleganteagle_Opscript_1_0_0
{
	meta:
		description = "Auto-generated rule - file eleganteagle_opscript.1.0.0.6"
		author = "Florian Roth (Nextron Systems)"
		id = "22855519-160c-57cf-b610-a611ca6813ed"
		date = "2016-12-17"
		modified = "2023-12-05"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_fvey_shadowbroker_dec16.yar#L119-L132"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3df5ba1a497ffe5306ed7966f25f69c30a5191e935c5638869a62b3cb2324f70"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "57e223318de0a802874642652b3dc766128f25d7e8f320c6f04c6f2659bb4f7f"

	strings:
		$x3 = "uploadnrun -e \"D=-ucIP_ADDRESS_OF_REDIR" ascii

	condition:
		1 of them
}
