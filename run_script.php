<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
	$website = $_POST["website"];
	$command = "bash ./unicorn.sh $website";
	exec($command, $output, $status);
	if ($status == 0) {
		echo "Script executed successfully.";
	} else {
		echo "Error executing script: " . implode("\n", $output);
	}
}
?>
