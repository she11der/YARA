import "pe"

rule SIGNATURE_BASE_Crack_Loader
{
	meta:
		description = "Auto-generated rule on file Loader.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "0c4c7b69-7739-5c1b-8c7c-4aaa724e4455"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L462-L473"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f4f79358a6c600c1f0ba1f7e4879a16d"
		logic_hash = "3380ace7c34c15dfd9a9625c8c4a1ed7e35c1cf3c2eca9b1e00dd0092d256150"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "NeoWait.exe"
		$s1 = "RRRRRRRW"

	condition:
		all of them
}
