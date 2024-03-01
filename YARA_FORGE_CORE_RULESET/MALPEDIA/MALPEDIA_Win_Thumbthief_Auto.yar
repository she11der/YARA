rule MALPEDIA_Win_Thumbthief_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "37aaa405-1531-5214-b674-b08465e47533"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thumbthief"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.thumbthief_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "f526be6ecad90c989de9ad949776796071b33db6ed80435843c6bf3aac7a3492"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { e9???????? 689c000000 b8???????? e8???????? 33db 8d4db4 895dec }
		$sequence_1 = { f6431002 0f85e1000000 85f6 0f44f3 89758c b800040000 66854310 }
		$sequence_2 = { ffb58cfeffff 8d8d30ffffff e8???????? 8d8de0feffff 807def00 7408 ffb5acfeffff }
		$sequence_3 = { f20f1085ecfeffff 8d8574ffffff 51 51 f20f110424 50 8d85f4feffff }
		$sequence_4 = { e8???????? c645fc02 8d8d58ffffff e8???????? c645fc03 8d8d18ffffff e8???????? }
		$sequence_5 = { bf48030000 8d85a4fcffff 57 6a00 50 e8???????? 83c40c }
		$sequence_6 = { eb77 68???????? eb70 68???????? eb69 8bc3 2d04130400 }
		$sequence_7 = { ff75f8 85c0 743c ff75f4 ba07000000 8bcf e8???????? }
		$sequence_8 = { e8???????? b8???????? e9???????? 8d4ddc e9???????? 8d4dbc e9???????? }
		$sequence_9 = { ff15???????? 8b4704 5f 85c0 740a 894508 5d }

	condition:
		7 of them and filesize <4235264
}
