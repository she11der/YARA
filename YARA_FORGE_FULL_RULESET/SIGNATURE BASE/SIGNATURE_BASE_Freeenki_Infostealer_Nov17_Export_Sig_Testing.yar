import "pe"

rule SIGNATURE_BASE_Freeenki_Infostealer_Nov17_Export_Sig_Testing : FILE
{
	meta:
		description = "Detects Freenki infostealer malware"
		author = "Florian Roth (Nextron Systems)"
		id = "929f9d41-2e71-5a86-b12f-489355bdf88d"
		date = "2017-11-28"
		modified = "2023-12-05"
		reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_rokrat.yar#L94-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2c6d8784aa976501a77441c4e705b7fdc9654277e8cd3f6d966967fb2e1cd724"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and pe.exports("getUpdate") and pe.number_of_exports==1
}
