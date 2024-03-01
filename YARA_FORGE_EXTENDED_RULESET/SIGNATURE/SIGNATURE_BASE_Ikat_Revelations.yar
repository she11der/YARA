import "pe"

rule SIGNATURE_BASE_Ikat_Revelations
{
	meta:
		description = "iKAT hack tool showing the content of password fields - file revelations.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c5ef2c2a-c9c0-5c3a-bbcc-0b0949527850"
		date = "2014-05-11"
		modified = "2023-12-05"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L796-L813"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c4e217a8f2a2433297961561c5926cbd522f7996"
		logic_hash = "0f3aa9e784beb7de8b560ecde8cc06d49e07f5e4ea4acb233ec9ac007179d7a3"
		score = 75
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "The RevelationHelper.DLL file is corrupt or missing." fullword ascii
		$s8 = "BETAsupport@snadboy.com" fullword wide
		$s9 = "support@snadboy.com" fullword wide
		$s14 = "RevelationHelper.dll" fullword ascii

	condition:
		all of them
}
