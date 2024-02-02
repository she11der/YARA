rule MALPEDIA_Win_Vigilant_Cleaner_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "a55582e3-616b-5a05-b673-fe9235d58867"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vigilant_cleaner"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.vigilant_cleaner_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "c5f2d2527d22c9ed364af085c79f4bf3cbb7661e8edd11d29a8f6f3321af29a9"
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
		$sequence_0 = { 53 b868584d56 bb00000000 b90a000000 ba58560000 ed 5b }
		$sequence_1 = { ed 5b 59 5a }
		$sequence_2 = { b90a000000 ba58560000 ed 5b }
		$sequence_3 = { b90a000000 ba58560000 ed 5b 59 5a }
		$sequence_4 = { bb00000000 b90a000000 ba58560000 ed 5b }
		$sequence_5 = { bb00000000 b90a000000 ba58560000 ed 5b 59 }
		$sequence_6 = { b90a000000 ba58560000 ed 5b 59 }
		$sequence_7 = { bb00000000 b90a000000 ba58560000 ed 5b 59 5a }
		$sequence_8 = { b868584d56 bb00000000 b90a000000 ba58560000 ed 5b }
		$sequence_9 = { ba58560000 ed 5b 59 }

	condition:
		7 of them and filesize <1181696
}