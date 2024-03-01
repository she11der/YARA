import "pe"

rule ESET_Stantinko_Wsaudio
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "623f4ac7-03ec-52df-b7bf-0a2055453c52"
		date = "2017-07-17"
		modified = "2017-07-20"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/stantinko/stantinko.yar#L211-L233"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "45d92f1475f316ba50a9a4a3dd519d1186ed16c68bd2debe326736a1e3154562"
		score = 75
		quality = 80
		tags = ""
		Author = "Marc-Etienne M.Léveillé"
		Description = "Stantinko wsaudio component"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "GetInterface"
		$s2 = "wsaudio.dll"
		$s3 = "Global\\Wsaudio_Initialize"
		$s4 = "SOFTWARE\\Classes\\%s.FieldListCtrl.1\\"

	condition:
		2 of them
}
