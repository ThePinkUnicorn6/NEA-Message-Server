﻿using System;
using System.IO;
using System.Net;
using System.Web;
using System.Text;
using Newtonsoft.Json;
using System.Text.Json.Serialization;
using System.Data.SQLite;
using System.Security.Cryptography;
using System.Collections;
using System.ComponentModel.Design;

class MessageServer
{
    const string typeJson = "application/json"; // For ease of use when sending a response.
    static readonly string logPath = @"logs\Server_" + DateTime.Now.ToString("yyyy-MM-dd_HH.mm.ss") + ".log"; // Cannot use a const because the time can't be calculated at compilation.
    static void Main(string[] args)
    {
        const string connectionString = "Data Source=data.db; Version=3; New=True; Compress=True;";
        using (var con = new SQLiteConnection(connectionString)) 
        {
            con.Open();
            log("DEBUG", "Using SQLite version: " + con.ServerVersion);
        }
        createDB(connectionString);
        const string url = "http://localhost:8080/";// Sets up http server
        HttpListener listener = new HttpListener();
        listener.Prefixes.Add(url);
        listener.Start(); 
        Console.WriteLine("Listening for requests on " + url);
        log("INFO", "Started server at " + url);
        while (true)
        {
            HttpListenerContext context = listener.GetContext();
            Uri uri = new Uri(context.Request.Url.ToString());
            log("INFO", context.Request.UserHostAddress.ToString() + " accessed " + uri.AbsolutePath.ToString());
            string responseMessage;
            try // This try catch should hopefully never run, but if needed it will stop the server from crashing.
            {
                switch (uri.AbsolutePath) // Calls function used for each api endpoint
                {
                    case "/api/content/getMessages": apiGetMessages(context, uri, connectionString); break;
                    case "/api/content/sendMessage": apiSendMessage(context, uri, connectionString); break;
                    case "/api/user/getInfo": apiGetUserInfo(context, uri, connectionString); break;
                    case "/api/directMessage/create": apiCreateChannel(context, uri, true, connectionString); break;
                    case "/api/guild/createChannel": apiCreateChannel(context, uri, false, connectionString); break;
                    case "/api/guild/create": apiCreateGuild(context, uri, connectionString); break;
                    case "/api/guild/listGuilds": apiListGuilds(context, uri, connectionString); break;
                    case "/api/guild/setDetails": apiSetGuildDetails(context, uri, connectionString); break;
                    case "/api/guild/createInvite": apiCreateInvite(context, uri, connectionString); break;
                    case "/api/account/create": apiAddUser(context, uri, connectionString); break;
                    case "/api/account/login": apiLogin(context, uri, connectionString); break;
                    case "/api/account/login/tokenToUserID": apiReturnUserIDFromToken(context, uri, connectionString); break;
                    default:
                    {
                        var responseJson = new
                        {
                            error = "Unrecognised request",
                            errcode = "UNRECOGNISED_URL"
                        };
                        responseMessage = JsonConvert.SerializeObject(responseJson);
                        sendResponse(context, typeJson, 404, responseMessage);
                        Console.WriteLine(uri.AbsolutePath);
                    }
                    break;
                }
            }

            catch (Exception e)
            {
                log("ERROR", "Unknown Error: \n", e);
                var responseJson = new { error = "Internal Server Error (500)", errcode = "UNKNOWN" };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                sendResponse(context, typeJson, 500, responseMessage);
            }
        }
    }
    static void createDB(string connectionString) // Opens connection to SQLite and creates the tables required
    {
        using (var con = new SQLiteConnection(connectionString)) 
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = "";
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblUsers' (
                'UserID'        CHAR(36),
                'UserName'      VARCHAR(20),
                'PassHash'      VARCHAR(64),
                'PublicKey'     TEXT,
                'Picture'       CHAR(36),
                'Description'   CHAR(36),
                PRIMARY KEY('UserID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblChannels' (
                'ChannelID'     CHAR(36),
                'ChannelName'   VARCHAR(20),
                'ChannelType'   INTEGER,
                'ChannelDesc'   VARCHAR(100),
                'IsDM'          BOOL,
                'GuildID'       CHAR(36),
                PRIMARY KEY('ChannelID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblMessages' (
                'ChannelID'     CHAR(36),
                'TimeSent'      REAL,
                'MessageID'     CHAR(36),
                'UserID'        CHAR(36),
                'MessageText'   TEXT,
                FOREIGN KEY('UserID') REFERENCES 'tblUsers'('UserID'),
                FOREIGN KEY('ChannelID') REFERENCES 'tblChannels'('ChannelID'),
                PRIMARY KEY('MessageID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblGuildConnections' (
                'UserID'        CHAR(36),
                'GuildID'       CHAR(36),
                'Admin'         BOOL,
                FOREIGN KEY('UserID') REFERENCES 'tblUsers'('UserID'),
                FOREIGN KEY('GuildID') REFERENCES 'tblGuilds'('GuildID'),
                PRIMARY KEY('UserID', 'GuildID')
            )";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblDMConnections' (
                'UserID'        CHAR(36),
                'ChannelID'     CHAR(36),
                FOREIGN KEY('UserID') REFERENCES 'tblUsers'('UserID'),
                FOREIGN KEY('ChannelID') REFERENCES 'tblChannels'('ChannelID'),
                PRIMARY KEY('UserID', 'ChannelID')
            )";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblTokens' (
                'Token'         CHAR(36),
                'UserID'        CHAR(36),
                PRIMARY KEY('Token'),
                FOREIGN KEY('UserID') REFERENCES 'tblUsers'('UserID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblGuilds' (
                'GuildID'       CHAR(36),
                'GuildName'     VARCHAR(36),
                'OwnerID'       CHAR(36),
                'GuildDesc'     VARCHAR(100),
                PRIMARY KEY('GuildID'),
                FOREIGN KEY('OwnerID') REFERENCES 'tblUsers'('UserID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblInvites' (
                'Code'          CHAR(8),
                'GuildID'       CHAR(36),
                PRIMARY KEY('Code'),
                FOREIGN KEY('GuildID') REFERENCES 'tblGuilds'('GuildID')
            );";
        }
    }
    static void sendResponse(HttpListenerContext context, string type, int code, string? responseMessage = null) // Sends data in response to a call from a client
    {
        if (string.IsNullOrEmpty(responseMessage))
        {
            context.Response.Headers.Clear();
            context.Response.StatusCode = code;
            context.Response.Close();
        }
        else
        {
            byte[] responseBytes = Encoding.UTF8.GetBytes(responseMessage);
            context.Response.ContentLength64 = responseBytes.Length;
            context.Response.ContentType = type;
            context.Response.StatusCode = code;
            Stream outputStream = context.Response.OutputStream;
            outputStream.Write(responseBytes, 0, responseBytes.Length);
            outputStream.Close();
        }
        Console.WriteLine("Sent response: " + responseMessage);
    }
    static string hash(string plaintext)
    {
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(plaintext)));
    }
    static void log(string type, string desc, Exception ex = null)
    {
        string time = DateTime.Now.ToString("MM/dd HH:mm:ss.fff");
        if(!Directory.Exists("logs"))
        {
            Directory.CreateDirectory("logs");
        }
        switch (type)
        {
            case "ERROR":
            {
                File.AppendAllText(logPath, time + " [!ERROR] " + desc + ex.ToString() + "\n\n");
            }break;
            case "INFO":
            {
                File.AppendAllText(logPath, time + " [INFO]   " + desc + "\n");
            }break;
            case "DEBUG":
            {
                File.AppendAllText(logPath, time + " [DEBUG]  " + desc + "\n");
            }break;
        }
    }
    static void apiGetMessages(HttpListenerContext context, Uri uri, string connectionString) // Fetches message data from db if user has permission, and returns it as a json array.
    {
        List<Message> messages = new List<Message>();
        int code;
        string responseMessage = "";
        string? channelID = context.Request.QueryString["channelID"];
        string? afterMessageID = context.Request.QueryString["afterMessageID"];
        string? token = context.Request.QueryString["token"];
        if (string.IsNullOrEmpty(channelID) | string.IsNullOrEmpty(token)) // If missing a perameter respond with an error
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 401;
        }
        else
        {
            string userID = getUserIDFromToken(token, connectionString);
            if (checkUserChannelPerms(connectionString, channelID, userID) > 0)
            {
                using (var con = new SQLiteConnection(connectionString))
                using (var cmd = new SQLiteCommand(con))
                {
                    con.Open();
                    // Will return all messages in a channel if AfterMessageID is not null, otherwise it will return only the messages after the message specified.
                    cmd.CommandText = @"SELECT tblUsers.UserID, UserName, MessageID, TimeSent, MessageText 
                                        FROM tblMessages, tblUsers
                                        WHERE tblMessages.ChannelID = @ChannelID
                                        AND tblMessages.UserID = tblUsers.UserID
                                        AND 
                                        (
                                            CASE 
                                                WHEN @AfterMessageID IS NOT NULL AND tblMessages.TimeSent > (
                                                    SELECT TimeSent
                                                    FROM tblMessages
                                                    WHERE MessageID = @AfterMessageID
                                                )
                                                OR @AfterMessageID IS NULL
                                                THEN true
                                                ELSE false
                                            END
                                        )
                                        LIMIT 50;"; 
                    cmd.Parameters.AddWithValue("AfterMessageID", afterMessageID);
                    cmd.Parameters.AddWithValue("ChannelID", channelID);
                    using (SQLiteDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read()) // Loops through each message and adds it to the message list
                        {
                            Message responseRow = new Message
                            {
                                UserID = reader.GetString(0),
                                UserName = reader.GetString(1),
                                ID = reader.GetString(2),
                                ChannelID = channelID,
                                Time = reader.GetDouble(3),
                                Text = reader.GetString(4)
                            };
                            messages.Add(responseRow);
                        }
                    }
                }
            }
            else
            {
                var responseJson = new { error = "You do not have permission to read messages in this channel", errcode = "FORBIDDEN" };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 403;
            }

            int i = 0;
            responseMessage += "[";
            foreach (Message message in messages) // Assembles the messages into JSON
            {
                string messageJson = JsonConvert.SerializeObject(message);
                responseMessage += messageJson;
                if (i < messages.Count - 1)
                {
                    responseMessage += ", ";
                }
                i++;
            }
            responseMessage += "]"; 
            code = 200;
        }

        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiSendMessage(HttpListenerContext context, Uri uri, string connectionString)
    {
        Message message = new Message
        {
            ID = Guid.NewGuid().ToString(),
            ChannelID = context.Request.QueryString["channelID"],
            Text = context.Request.QueryString["messageText"],
        };
        string? token = context.Request.QueryString["token"];
        int code;
        string? responseMessage;
        if (string.IsNullOrEmpty(message.ChannelID) | string.IsNullOrEmpty(message.Text) | string.IsNullOrEmpty(token))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }        
        else if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 401;
        }
        else
        {
            message.UserID = getUserIDFromToken(token, connectionString);
            if (checkUserChannelPerms(connectionString, message.ChannelID, message.UserID) > 0)
            {
                // TODO: check user permissions and channel type
                using (var con = new SQLiteConnection(connectionString))
                using (var cmd = new SQLiteCommand(con))
                {
                    con.Open();
                    cmd.CommandText = @"INSERT INTO tblMessages (ChannelID, TimeSent, MessageID, UserID, MessageText)
                                        VALUES (@ChannelID, unixepoch('subsec'), @MessageID, @UserID, @MessageText);";
                    cmd.Parameters.AddWithValue("ChannelID", message.ChannelID);
                    cmd.Parameters.AddWithValue("MessageID", message.ID);
                    cmd.Parameters.AddWithValue("UserID", message.UserID);
                    cmd.Parameters.AddWithValue("MessageText", message.Text);
                    cmd.ExecuteNonQuery();
                    cmd.CommandText = @"SELECT Username
                                        FROM tblUsers
                                        WHERE UserID = @UserID";
                    cmd.Parameters.AddWithValue("UserID", message.UserID);
                    message.UserName = (string)cmd.ExecuteScalar();
                    cmd.CommandText = @"SELECT TimeSent
                                        FROM tblMessages
                                        WHERE MessageID = @MessageID";
                    cmd.Parameters.AddWithValue("MessageID", message.ID);
                    message.Time = (Double)cmd.ExecuteScalar();

                    responseMessage = JsonConvert.SerializeObject(message);
                    code = 200;
                }
            }
            else
            {
                var responseJson = new { error = "You do not have permission to post in this channel", errcode = "FORBIDDEN" };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 403;
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    private static int checkUserChannelPerms(string connectionString, string channelID, string userID) // Gets the permissions of the user. 0 is not in channel, 1 is a normal user, 2 is administrator, 3 is owner.
    {
        // TODO: finish this
        bool inChannel;
        bool isAdmin;
        bool isOwner = false;
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"SELECT EXISTS(
                                    SELECT 1
                                    FROM tblGuildConnections, tblGuilds, tblChannels
                                    WHERE tblGuildConnections.UserID = @UserID 
                                    AND tblGuildConnections.GuildID = tblChannels.GuildID 
                                    AND tblChannels.ChannelID = @ChannelID

                                    UNION

                                    SELECT 1
                                    FROM tblDMConnections, tblChannels
                                    WHERE tblDMConnections.UserID = @UserID 
                                    AND tblDMConnections.ChannelID = @ChannelID
                                    );";  // Returns true if user is in the supplied Channel or DM
            cmd.Parameters.AddWithValue("UserID", userID);
            cmd.Parameters.AddWithValue("ChannelID", channelID);
            inChannel = (Int64)cmd.ExecuteScalar() > 0; //Convert integer 1 or 0 into boolean
            if (!inChannel) {return 0;}

            cmd.CommandText = @"SELECT Admin
                                FROM tblGuildConnections
                                JOIN tblGuilds ON tblGuilds.GuildID=tblGuildConnections.GuildID
                                JOIN tblChannels ON tblChannels.GuildID=tblGuilds.GuildID
                                WHERE UserID = '7ee8c1f5-6e6d-4647-a232-293b3bb0e1dc'
                                AND ChannelID = 'd29e41ae-1186-4387-b278-ec3940293134'";
            cmd.Parameters.AddWithValue("UserID", userID);
            cmd.Parameters.AddWithValue("ChannelID", channelID);
            isAdmin = (bool)cmd.ExecuteScalar();
            if (isAdmin) {return 2;}
            else return 1;
        }
        if      (isOwner)  {return 3;}
        else if (isAdmin)  {return 2;}
        else if (inChannel){return 1;}
        else               {return 0;}
    }
    static void apiGetUserInfo(HttpListenerContext context, Uri uri, string connectionString)
    {
        string? token = context.Request.QueryString["token"];
        string? requestedUserID = context.Request.QueryString["userID"];
        int code;
        string responseMessage;
        if (string.IsNullOrEmpty(token) | string.IsNullOrEmpty(requestedUserID))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }        
        else if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 401;
        }
        else
        {
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"SELECT UserID, UserName, Picture, Description
                FROM tblUsers
                WHERE UserID = @UserID";
                cmd.Parameters.AddWithValue("UserID", requestedUserID);
                using (SQLiteDataReader reader = cmd.ExecuteReader())
                {
                    if (!reader.Read())
                    {
                        var responseJson = new { error = "That UserID does not exist", errcode = "NOT_FOUND" };
                        responseMessage = JsonConvert.SerializeObject(responseJson);
                        code = 400;
                    }
                    else
                    {
                        string description = reader[3] == null ? null : reader[3].ToString();
                        User user = new User
                        {
                            ID = reader.GetString(0),
                            Name = reader.GetString(1),
                            Picture = reader.GetString(2),
                            Description = description
                        };
                        responseMessage = JsonConvert.SerializeObject(user);
                        code = 200;
                    }
                    sendResponse(context, typeJson, code, responseMessage);
                }
            }
        }
    }
    static void apiAddUser(HttpListenerContext context, Uri uri, string connectionString)
    {
        //Checks if user exists before adding them to the database. Will respond with an error if the user allready exists.
        string responseMessage;
        int code;
        string? userName = context.Request.QueryString["userName"];
        string? passHash = context.Request.QueryString["passHash"];
        string? publicKey = context.Request.QueryString["publicKey"];
        if (string.IsNullOrEmpty(userName) | string.IsNullOrEmpty(publicKey) | string.IsNullOrEmpty(passHash))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else
        {
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"
                SELECT EXISTS(
                    SELECT 1 
                    FROM tblUsers
                    WHERE UserName = @UserName
                )";
                cmd.Parameters.AddWithValue("UserName", userName);
                bool userTaken = (Int64)cmd.ExecuteScalar() > 0;
                if (userTaken)
                {
                    var responseJson = new { error = "User with that name already exists", errcode = "NAME_IN_USE"};
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 400;
                }
                else
                {
                    string userID = Guid.NewGuid().ToString();
                    cmd.CommandText = @"INSERT INTO tblUsers (UserID, UserName, PassHash)
                                        VALUES (@UserID, @UserName, @PassHash)";
                    cmd.Parameters.AddWithValue("UserID", userID);
                    cmd.Parameters.AddWithValue("UserName", userName);
                    cmd.Parameters.AddWithValue("PassHash", passHash);
                    cmd.ExecuteNonQuery();
                    var responseJson = new { token = createToken(userID, connectionString) };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 200;
                }  
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiLogin(HttpListenerContext context, Uri uri, string connectionString) // Checks if the supplied username and password are correct, and returns a token if they are
    {
        string responseMessage;
        int code;
        string? userName = context.Request.QueryString["userName"];
        string? passHash = context.Request.QueryString["passHash"];
        if (string.IsNullOrEmpty(userName) | string.IsNullOrEmpty(passHash))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else
        {
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"SELECT UserID
                                    FROM tblUsers
                                    WHERE UserName = @UserName AND PassHash = @PassHash;";
                cmd.Parameters.AddWithValue("UserName", userName);
                cmd.Parameters.AddWithValue("PassHash", passHash);
                object temp = cmd.ExecuteScalar();
                string userID = temp == null ? null : (string)temp; // If the select returns null, store string as null, otherwise as a string.
                bool correctCredentials = !string.IsNullOrEmpty(userID);
                if (correctCredentials)
                {
                    var responseJson = new { token = createToken(userID, connectionString) };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 200;  
                }
                else
                {
                    var responseJson = new { error = "Incorrect username or password.", errcode = "FORBIDDEN" };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 403;
                }
            }
            sendResponse(context, typeJson, code, responseMessage);
        }
    }
    static void apiCreateChannel(HttpListenerContext context, Uri uri, bool isDM, string connectionString)
    {
        string? channelName = context.Request.QueryString["channelName"];
        string? token = context.Request.QueryString["token"];
        string? guildID = context.Request.QueryString["guildID"];
        string? userID2 = getUserIDFromUsername(context.Request.QueryString["userToAdd"], connectionString);
        string? responseMessage;
        int? channelType;
        if (!isDM)
        {
            channelType = int.Parse(context.Request.QueryString["channelType"]);
        }
        else 
        {
            channelType = null;
        }
        int code;

        if (string.IsNullOrEmpty(channelName) | string.IsNullOrEmpty(token) | (isDM & string.IsNullOrEmpty(userID2)) | (!isDM & string.IsNullOrEmpty(guildID)))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 401;
        }
        else
        {
            string userID1 = getUserIDFromToken(token, connectionString);
            if (isDM)
            {
                if (userID1 != userID2)
                {
                    createDM(userID1, userID2, connectionString);
                    responseMessage = null;
                    code = 200;
                }
                else
                {
                    var responseJson = new { error = "You cannot add yourself to your own DM", errcode = "INVALID_DATA" };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 400;
                }
            }
            else
            {
                bool guildExists = checkGuildExists(guildID, connectionString);
                if (guildExists)
                {
                    createChannel(channelName, guildID, (int)channelType, connectionString);
                    responseMessage = null;
                    code = 200;
                }
                else
                {
                    var responseJson = new { error = "Invalid GuildID", errcode = "INVALID_DATA" };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 400;
                }
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void createDM(string userID1, string userID2, string connectionString)
    {
        string channelID = Guid.NewGuid().ToString();
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"INSERT INTO tblChannels(ChannelID, ChannelName, ChannelType, IsDM)
                                VALUES (@ChannelID, NULL, 1, 1);";
            cmd.Parameters.AddWithValue("ChannelID", channelID);
            cmd.ExecuteNonQuery();
            // Add user to DM
            cmd.CommandText = @"INSERT INTO tblDMConnections (UserID, ChannelID)
                                VALUES (@UserID, @ChannelID);";
            cmd.Parameters.AddWithValue("UserID", userID1);
            cmd.Parameters.AddWithValue("ChannelID", channelID);
            cmd.ExecuteNonQuery();
            // Add other user to DM
            cmd.CommandText = @"INSERT INTO tblDMConnections (UserID, ChannelID)
                                VALUES (@UserID, @ChannelID);";
            cmd.Parameters.AddWithValue("UserID", userID2);
            cmd.Parameters.AddWithValue("ChannelID", channelID);
            cmd.ExecuteNonQuery();
        }
    }
    static void createChannel(string channelName, string guildID, int channelType, string connectionString)
    {
        string channelID = Guid.NewGuid().ToString();
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"INSERT INTO tblChannels(ChannelID, ChannelName, ChannelType, IsDM, GuildID)
                                VALUES (@ChannelID, @ChannelName, @ChannelType, 0, @GuildID);";
            cmd.Parameters.AddWithValue("ChannelID", channelID);
            cmd.Parameters.AddWithValue("ChannelName", channelName);
            cmd.Parameters.AddWithValue("ChannelType", channelType);
            cmd.Parameters.AddWithValue("GuildID", guildID);
            cmd.ExecuteNonQuery();
        }
    }
    static void apiCreateGuild(HttpListenerContext context, Uri uri, string connectionString)
    {
        string? guildName = context.Request.QueryString["guildName"];
        string? token = context.Request.QueryString["token"];
        string guildID = Guid.NewGuid().ToString();
        string responseMessage;
        int code;

        if (string.IsNullOrEmpty(guildName) | string.IsNullOrEmpty(token))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 401;
        }
        else 
        {
            string userID = getUserIDFromToken(token, connectionString);
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"INSERT INTO tblGuilds(GuildID, GuildName, OwnerID)
                                    VALUES (@GuildID, @GuildName, @OwnerID);";
                cmd.Parameters.AddWithValue("GuildID", guildID);
                cmd.Parameters.AddWithValue("GuildName", guildName);
                cmd.Parameters.AddWithValue("@OwnerID", userID);
                cmd.ExecuteNonQuery();
                cmd.CommandText = @"INSERT INTO tblGuildConnections(UserID, GuildID, Admin)
                                    VALUES (@UserID, @GuildID, 1);";
                cmd.Parameters.AddWithValue("UserID", userID);
                cmd.Parameters.AddWithValue("GuildID", guildID);
                cmd.ExecuteNonQuery();
            }
            createChannel("General", guildID, 1, connectionString);
            var responseJson = new { GuildID = guildID};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 200;
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiListGuilds(HttpListenerContext context, Uri uri, string connectionString) // Returns all guilds the user is part of, and the channels in each guild.
    {
        string? token = context.Request.QueryString["token"];
        string responseMessage;
        int code;
        if (string.IsNullOrEmpty(token))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 401;
        }
        else 
        {
            List<dynamic> dbResponse = new List<dynamic>{};
            string userID = getUserIDFromToken(token, connectionString);
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"SELECT tblGuilds.GuildID, GuildName, OwnerID, GuildDesc, ChannelID, ChannelName, ChannelType, ChannelDesc
                FROM tblGuilds, tblGuildConnections, tblChannels, tblUsers
                WHERE tblUsers.UserID = @UserID 
                AND tblUsers.UserID = tblGuildConnections.UserID
                AND tblGuildConnections.GuildID = tblGuilds.GuildID
                And tblGuilds.GuildID = tblChannels.GuildID
                ORDER BY GuildName ASC;";
                cmd.Parameters.AddWithValue("UserID", userID);
                using (SQLiteDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string guildDesc = reader[3] == null ? null : reader[3].ToString();
                        string channelDesc = reader[7] == null ? null : reader[7].ToString(); // If description is null, set the variable to null to stop it from erroring.
                        var responseRow = new
                        {
                            GuildID = reader.GetString(0),
                            GuildName = reader.GetString(1),
                            GuildOwnerID = reader.GetString(2),
                            GuildDesc = guildDesc,
                            ChannelID = reader.GetString(4),
                            ChannelName = reader.GetString(5),
                            ChannelType = reader.GetInt32(6),
                            ChannelDesc = channelDesc
                        };
                        dbResponse.Add(responseRow);
                    }
                }
            }
            string guildsJson = "[{"; 
            for (int i = 0; i < dbResponse.Count; i++) // Build the json response string
            {
                if (i == 0 || dbResponse[i].GuildID != dbResponse[i - 1].GuildID) // If the guildID is different from the previous iteration, start a new guild item in the JSON array.
                {
                    guildsJson += "\"guildName\": \"" + dbResponse[i].GuildName + "\", ";
                    guildsJson += "\"guildID\": \"" + dbResponse[i].GuildID + "\", ";
                    guildsJson += "\"guildOwnerID\": \"" + dbResponse[i].GuildOwnerID + "\", ";
                    guildsJson += "\"guildDesc\": \"" + dbResponse[i].GuildDesc + "\", ";
                    guildsJson += "\"channels\": [";
                }
                guildsJson += "{"; // Build channel array in guilds json array.
                guildsJson += "\"channelName\": \"" + dbResponse[i].ChannelName + "\", ";
                guildsJson += "\"channelID\": \"" + dbResponse[i].ChannelID + "\", ";
                guildsJson += "\"channelDesc\": \"" + dbResponse[i].ChannelDesc + "\", ";
                guildsJson += "\"channelType\": \"" + dbResponse[i].ChannelType + "\"}";
                if (dbResponse.Count > i + 1 && dbResponse[i].GuildID == dbResponse[i + 1].GuildID)
                {
                    guildsJson += ", "; // Add comma if needed.
                }
                else if (dbResponse.Count > i + 1 && dbResponse[i].GuildID != dbResponse[i + 1].GuildID)
                {
                    guildsJson += "]}, {"; // Add closing brackets and opening bracket at start of new guild item.
                }
            }
            if (dbResponse.Count != 0) // If there was stuff returned, end the array.
            {
                guildsJson += "]";
            }
            guildsJson += "}]"; // Add closing brackets.
            responseMessage = guildsJson;
            code = 200;            
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiSetGuildDetails(HttpListenerContext context, Uri uri, string connectionString)
    {
        string? token = context.Request.QueryString["token"];
        string? guildID = context.Request.QueryString["guildID"];
        string? guildName = context.Request.QueryString["guildName"];
        string? guildDesc = context.Request.QueryString["guildDesc"];
        string responseMessage;
        int code;

        if (string.IsNullOrEmpty(guildID) | string.IsNullOrEmpty(token))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 401;
        }
        else if (!checkGuildExists(guildID, connectionString))
        {
            var responseJson = new { error = "Invalid GuildID", errcode = "INVALID_GUILDID" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else 
        {
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open(); 
                // Checks if it should update the guilds name, description or both
                if (!string.IsNullOrEmpty(guildName) & !string.IsNullOrEmpty(guildDesc))
                {
                    cmd.CommandText = @"UPDATE tblGuilds
                    SET GuildName = @GuildName, GuildDesc = @GuildDesc
                    WHERE GuildID = @GuildID;";
                    cmd.Parameters.AddWithValue("GuildName", guildName);
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    cmd.Parameters.AddWithValue("GuildDesc", guildDesc);
                }
                else if (string.IsNullOrEmpty(guildName) & !string.IsNullOrEmpty(guildDesc))
                {
                    cmd.CommandText = @"UPDATE tblGuilds
                    SET GuildDesc = @GuildDesc
                    WHERE GuildID = @GuildID;";
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    cmd.Parameters.AddWithValue("GuildDesc", guildDesc);
                }
                else if (!string.IsNullOrEmpty(guildName) & string.IsNullOrEmpty(guildDesc))
                {
                    cmd.CommandText = @"UPDATE tblGuilds
                    SET GuildName = @GuildName
                    WHERE GuildID = @GuildID;";
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    cmd.Parameters.AddWithValue("GuildName", guildName);
                }
                cmd.ExecuteNonQuery();
            }
            code = 200;
            responseMessage = null;
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiCreateInvite(HttpListenerContext context, Uri uri, string connectionString)
    {
        string? guildID = context.Request.QueryString["guildID"];
        string? token = context.Request.QueryString["token"];

        Random rnd = new Random();
        string inviteCode = "";
        for (int i = 0; i < 8; i++)
        {
            inviteCode += ((char)(rnd.Next(1,26) + 64)).ToString();
        }
        // TODO: add invite to db and return it to user
        using (var con = new SQLiteConnection(connectionString)) 
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"INSERT INTO tblInvites (Code, GuildID)
                                VALUS (@Code, @GuildID)";
            cmd.Parameters.AddWithValue("Code", inviteCode);
            cmd.Parameters.AddWithValue("GuildID", guildID);
        }
    }
    static string createToken(string userID, string connectionString)// Generates a token that the client can then use to authenticate with
    {
        string token = Guid.NewGuid().ToString();
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"INSERT INTO tblTokens(UserID, Token)
                                VALUES (@UserID, @Token)";
            cmd.Parameters.AddWithValue("UserID", userID);
            cmd.Parameters.AddWithValue("Token", token);
            cmd.ExecuteNonQuery();
        }
        return token;
    }
    static string getUserIDFromToken(string token, string connectionString)
    {
        string userID;
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"SELECT UserID
                                FROM tblTokens
                                WHERE Token = @Token;";
            cmd.Parameters.AddWithValue("Token", token);
            using (SQLiteDataReader reader = cmd.ExecuteReader())
            {
                reader.Read();
                userID = Convert.ToString(reader["UserID"]);
            }
        }
        return userID;
    }
    static bool tokenValid(string? token, string connectionString)
    {
        bool valid;
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"
            SELECT EXISTS(
                SELECT 1 
                FROM tblTokens
                WHERE Token = @Token
            )";
            cmd.Parameters.AddWithValue("Token", token);
            valid = (Int64)cmd.ExecuteScalar() > 0;
        }
        return valid;
    }
    static void apiReturnUserIDFromToken(HttpListenerContext context, Uri uri, string connectionString) // Returns the UserID to the user when given a token.
    {
        string? token = context.Request.QueryString["token"];
        string userID;
        string responseMessage;
        int code;
        if (string.IsNullOrEmpty(token))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 401;
        }
        else
        {
            userID = getUserIDFromToken(token, connectionString);
            var responseJson = new { UserID = userID };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 200;
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static string getUserIDFromUsername(string? userName, string connectionString)// Looks up a UserName and returns the asociated UserID
    {
        string userID;
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"SELECT UserID
                                FROM tblUsers
                                WHERE UserName = @UserName";
            cmd.Parameters.AddWithValue("UserName", userName);

            object temp = cmd.ExecuteScalar();
            userID = temp == null ? null : (string)temp; // If the select returns null, store string as null, otherwise as a string.
        }
        return userID;
    }
    static bool checkGuildExists(string guildID, string connectionString)
    {
        bool guildExists;
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"
                    SELECT EXISTS(
                        SELECT 1 
                        FROM tblGuilds
                        WHERE GuildID = @GuildID
                    );";
            cmd.Parameters.AddWithValue("GuildID", guildID);
            guildExists = (Int64)cmd.ExecuteScalar() > 0; // Chech if guild exists
        }
        return guildExists;
    }
}