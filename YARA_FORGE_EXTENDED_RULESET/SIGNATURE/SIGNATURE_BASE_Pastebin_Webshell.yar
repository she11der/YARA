rule SIGNATURE_BASE_Pastebin_Webshell
{
	meta:
		description = "Detects a web shell that downloads content from pastebin.com http://goo.gl/7dbyZs"
		author = "Florian Roth (Nextron Systems)"
		id = "256051ed-da33-52b4-8bfb-ab990648d8fb"
		date = "2015-01-13"
		modified = "2023-12-05"
		reference = "http://goo.gl/7dbyZs"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9149-L9171"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e71429e9280c37a90ee77be888ae743a86521d3632afc4eeec480b82a22a1445"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "file_get_contents(\"http://pastebin.com" ascii
		$s1 = "xcurl('http://pastebin.com/download.php" ascii
		$s2 = "xcurl('http://pastebin.com/raw.php" ascii
		$x0 = "if($content){unlink('evex.php');" ascii
		$x1 = "$fh2 = fopen(\"evex.php\", 'a');" ascii
		$y0 = "file_put_contents($pth" ascii
		$y1 = "echo \"<login_ok>" ascii
		$y2 = "str_replace('* @package Wordpress',$temp" ascii

	condition:
		1 of ($s*) or all of ($x*) or all of ($y*)
}
