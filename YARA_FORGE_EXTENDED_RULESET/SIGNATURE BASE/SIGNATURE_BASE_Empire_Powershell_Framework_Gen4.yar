rule SIGNATURE_BASE_Empire_Powershell_Framework_Gen4 : FILE
{
	meta:
		description = "Detects Empire component"
		author = "Florian Roth (Nextron Systems)"
		id = "c390638a-0eb1-576d-a08c-203c31d414f3"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L519-L545"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "314574a463f9cc772702d5e3358f5280b2805298fedb89c14786518a4832d63b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "743c51334f17751cfd881be84b56f648edbdaf31f8186de88d094892edc644a9"
		hash2 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash3 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash4 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
		hash5 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"
		hash6 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
		hash7 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"
		hash8 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
		hash9 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
		hash10 = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"

	strings:
		$s1 = "Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }" fullword ascii
		$s2 = "# Get a handle to the module specified" fullword ascii
		$s3 = "$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))" fullword ascii
		$s4 = "$DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <4000KB and 1 of them ) or all of them
}
