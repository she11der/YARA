rule SIGNATURE_BASE_Webshell_ASP_Zehir4
{
	meta:
		description = "Web Shell - file zehir4.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L998-L1011"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7f4e12e159360743ec016273c3b9108c"
		logic_hash = "aa3e07ee6369dd5f86f28a53c8e45391de718d4935021339a7b47829b5196f54"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"

	condition:
		all of them
}
