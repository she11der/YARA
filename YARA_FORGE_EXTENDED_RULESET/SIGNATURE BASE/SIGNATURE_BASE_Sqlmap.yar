import "pe"

rule SIGNATURE_BASE_Sqlmap
{
	meta:
		description = "This signature detects the SQLMap SQL injection tool"
		author = "Florian Roth (Nextron Systems)"
		id = "55a72fe6-f82d-5d55-842f-5d7e1cfcc9fa"
		date = "2014-01-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L156-L169"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9c248c856c3d91a282012489b53dc9e15569e1bb1a5c9f5e3c7938f7ce0c3157"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "except SqlmapBaseException, ex:"

	condition:
		1 of them
}
