rule MALPEDIA_Win_Boldmove_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "ede55e68-ab48-582c-bf7e-2cb826551211"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.boldmove"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.boldmove_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "d529b7724e2e647d4848b38aca8e76a61b2caa5c4bf1c77fa8242a3dc71a9c2d"
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
		$sequence_0 = { 0fb655e4 d3e2 8b8b24300000 09d0 880431 31c0 }
		$sequence_1 = { 891c24 e8???????? 893424 e8???????? 8b442434 85c0 }
		$sequence_2 = { 0f85cf060000 c744246800000000 8b4c2434 b801000000 85c9 0f4fc1 8984249c000000 }
		$sequence_3 = { 83cd02 89442448 e9???????? 8d4701 83cd08 89442448 }
		$sequence_4 = { e8???????? 89c5 8b442438 892c24 89442404 e8???????? 8b4c2424 }
		$sequence_5 = { 8b442420 89fb 8b10 e9???????? 85f6 7e03 83ee01 }
		$sequence_6 = { 8b8314100000 31d2 39d0 740c 39b49318100000 7418 42 }
		$sequence_7 = { 85db 0f84561d0000 81fe00040000 b800040000 0f4ec6 890424 89442440 }
		$sequence_8 = { 8d4f04 7415 837c242801 0f8473050000 837c242805 7503 0fbec0 }
		$sequence_9 = { 8b8310080000 31d2 39d0 740c 39b49314080000 }

	condition:
		7 of them and filesize <242688
}
