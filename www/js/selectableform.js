v = "applicationform";

document.getElementById('nav-add-tab').addEventListener("click",function(){
	console.log("click");

	if ($("#uploadtypeselector").attr("name") == "") {
	v = document.getElementById('uploadtypeselector').value;
	} else {
		v = $("#uploadtypeselector").attr("name");
	}
	console.log("if " + v);

	

});
	changeview(v);


	$("#uploadtypeselector").change(function() {
		val = $(this).val();
		deleteview(v);
		changeview(val);
		v = val;
	});

function changeview(val) {
	console.log("changed to: " + val);
	document.getElementById(val).style.display = "block";
}

function deleteview(val) {
	console.log("Deleted view: " + val);
	document.getElementById(val).style.display = "none";
}



