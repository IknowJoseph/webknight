// UpdateMSI.js <msi-file>
//based on EnableLaunchApplication.js



// Constant values from Windows Installer
var msiOpenDatabaseModeTransact = 1;

var msiViewModifyInsert         = 1
var msiViewModifyUpdate         = 2
var msiViewModifyAssign         = 3
var msiViewModifyReplace        = 4
var msiViewModifyDelete         = 6



if (WScript.Arguments.Length != 1)
{
	WScript.StdErr.WriteLine(WScript.ScriptName + " file");
	WScript.Quit(1);
}

var filespec = WScript.Arguments(0);
var installer = WScript.CreateObject("WindowsInstaller.Installer");
var database = installer.OpenDatabase(filespec, msiOpenDatabaseModeTransact);

var sql
var view
var record

try{
		UpdateFiles(".");
		TryUpdateFile("readme.htm");//file case mismatch
		
		database.Commit();
}catch(e){

		WScript.Echo(e.message);
		WScript.Quit(1);
}

function UpdateFiles(path)
{
	var fso, folder, fc, fn;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	folder = fso.GetFolder(path);
	fc = new Enumerator(folder.files);
	for (; !fc.atEnd(); fc.moveNext())
	{
		fn = fso.GetFileName(fc.item());
		TryUpdateFile(fn);
	}
}

function TryUpdateFile(filename)
{
	try
	{
		var fileId = FindFileIdentifier(database, filename);
		if (!fileId)
			throw new Error("Unable to find '" + filename + "' in File table");

		UpdateFile(filename);
	}
	catch(e)
	{
		WScript.Echo(e.message);
	}
}

function GetFileSize(fileName)
{
	var fso, f;
	fso = new ActiveXObject("Scripting.FileSystemObject");
    f = fso.GetFile(fileName);
	return f.Size;
}

function UpdateFile(fileId)
{
	try{
		var fileSize = GetFileSize(fileId);
		WScript.Echo("Updating the File table..." + fileId);
		sql = "UPDATE File SET FileSize = " + fileSize + " WHERE File = '" + fileId + "'";
		//WScript.Echo(sql);
		view = database.OpenView(sql);
		view.Execute();
		view.Close();
	}catch(e){
		WScript.Echo(e.message);
		var record = installer.LastErrorRecord;
		WScript.Echo(record.FormatText());
	}
}

function FindFileIdentifier(database, fileName)
{
	var sql
	var view
	var record

	// First, try to find the exact file name
	sql = "SELECT `File` FROM `File` WHERE `FileName`='" + fileName + "'";
	view = database.OpenView(sql);
	view.Execute();
	record = view.Fetch();
	if (record)
	{
		var value = record.StringData(1);
		view.Close();
		return value;
	}
	view.Close();

	// The file may be in SFN|LFN format.  Look for a filename in this case next
	sql = "SELECT `File`, `FileName` FROM `File`";
	view = database.OpenView(sql);
	view.Execute();
	record = view.Fetch();
	while (record)
	{
		if (StringEndsWith(record.StringData(2), "|" + fileName))
		{
			var value = record.StringData(1);
			view.Close();
			return value;
		}

		record = view.Fetch();
	}
	view.Close();
	
}

function StringEndsWith(str, value)
{
	if (str.length < value.length)
		return false;

	return (str.indexOf(value, str.length - value.length) != -1);
}
