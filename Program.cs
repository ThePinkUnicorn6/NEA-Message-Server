﻿using System;
using System.IO;
using System.Net;
using System.Web;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Data.SQLite;
using System.Security.Cryptography;
class MessageServer
{
    static void Main(string[] args)
    {
        const string connectionString = "Data Source=data.db; Version=3; New=True; Compress=True;";
        createDB(connectionString);
        
        const string url = "http://*:8080/";//sets up http server
        HttpListener listener = new HttpListener();
        listener.Prefixes.Add(url);
        listener.Start(); //starts http server
        Console.WriteLine("Listening for requests on " + url);
        while (true)
        {
            HttpListenerContext context = listener.GetContext();
            Uri uri = new Uri(context.Request.Url.ToString());
            string responseMessage;
            switch (uri.AbsolutePath) //calls function used for each api endpoint
            {
                case "/api/content/getMessages": getMessages(context, uri, connectionString); break;
                case "/api/content/sendMessage": sendMessage(context, uri, connectionString); break;
                case "/api/groups/createChat": createChat(context, uri, 0, connectionString); break;
                case "/api/groups/createPrivateChat": createChat(context, uri, 1, connectionString); break;
                case "/api/account/addUser": addUser(context, uri, connectionString); break;
                case "/api/login": login(context, uri, connectionString); break;
                default:
                {
                    var responseJson = new
                    {
                        error = "Unrecognised request",
                        errcode = "UNRECOGNISED_URL"
                    };
                    responseMessage = JsonSerializer.Serialize(responseJson);
                    sendResponse(context, "application/json", 404, responseMessage);
                    Console.WriteLine(uri.AbsolutePath);
                }
                break;
            }
        }
    }
    static void createDB(string connectionString)//opens connection to SQLite and creates the tables required
    {
        using (var con = new SQLiteConnection(connectionString)) 
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblUsers' (
                'UserID'        CHAR(36) PRIMARY KEY,
                'UserName'      VARCHAR(20),
                'PassHash'      VARCHAR(64),
                'PublicKey'     TEXT
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblMessages' (
                'ChatID'        CHAR(36),
                'TimeSent'      INT,
                'MessageID'	    TEXT,
                'UserID'	    CHAR(36),
                'MessageText'	TEXT,
                FOREIGN KEY('UserID') REFERENCES 'tblUsers'('UserID'),
                PRIMARY KEY('MessageID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblChats' (
                'ChatID'        CHAR(36),
                'ChatName'      VARCHAR(20),
                'IsDM'          BOOL,
                PRIMARY KEY('ChatID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblConnections' (
                'UserID'        CHAR(36),
                'ChatID'        CHAR(36),
                'Admin'         BOOL,
                FOREIGN KEY('UserID') REFERENCES 'tblUsers'('UserID'),
                FOREIGN KEY('ChatID') REFERENCES 'tblChats'('ChatID')
            )";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblTokens' (
                'Token'	        CHAR(36),
                'UserID'        CHAR(36),
                PRIMARY KEY('Token'),
                FOREIGN KEY('UserID') REFERENCES 'tblUsers'('UserID')
            );";
            cmd.ExecuteNonQuery();
        }
    }
    static void sendResponse(HttpListenerContext context, string type, int code, string? responseMessage = null) //sends data in response to a call from a client
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
    }
    static string hash(string plaintext)
    {
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(plaintext)));
    }
    static void getMessages(HttpListenerContext context, Uri uri, string connectionString)//Fetches message data from db if user has permission, and returns it as a json array.
    {
        List<string[]> messages = new List<string[]>();
        int code = 200;
        string responseMessage = "";
        string? chatID = context.Request.QueryString["chatID"];
        string? offset = context.Request.QueryString["offset"];
        if (string.IsNullOrEmpty(chatID)) // If missing a perameter respond with an error
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonSerializer.Serialize(responseJson);
            code = 400;
        }
        else
        {
            if (string.IsNullOrEmpty(offset)) offset = "0";
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"SELECT tblUsers.UserID, UserName, MessageID, TimeSent, MessageText
                                    FROM tblMessages, tblUsers, tblChats
                                    WHERE tblChats.ChatID = @ChatID
                                    AND tblMessages.UserID = tblUsers.UserID
                                    LIMIT 50 OFFSET @offset;";
                cmd.Parameters.AddWithValue("@ChatID", chatID);
                cmd.Parameters.AddWithValue("@offset", offset);
                using (SQLiteDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        messages.Add(new string[] {reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt32(3).ToString(), reader.GetString(4)});
                    }
                }
            }
            int i = 0;
            responseMessage += "[";
            foreach (string[] message in messages)
            {

                var messageObj = new
                {
                    UserID = message[0],
                    UserName = message[1],
                    MessageID = message[2],
                    TimeSent = message[3],
                    MessageText = message[4]
                };
                string messageJson = JsonSerializer.Serialize(messageObj);
                responseMessage += messageJson;
                if (i < messages.Count - 1)
                {
                    responseMessage += ", ";
                }
                i++;
                code = 200;
            }
            responseMessage += "]"; 
        }

        sendResponse(context, "application/json", code, responseMessage);
    }
    static void sendMessage(HttpListenerContext context, Uri uri, string connectionString)
    {
        string? chatID = context.Request.QueryString["chatID"];
        string? messageText = context.Request.QueryString["messageText"];
        string? token = context.Request.QueryString["token"];
        string messageID = Guid.NewGuid().ToString();
        int code;
        string? responseMessage;
        if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonSerializer.Serialize(responseJson);
            code = 401;
        }
        else if (string.IsNullOrEmpty(chatID) | messageText is null | string.IsNullOrEmpty(token))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonSerializer.Serialize(responseJson);
            code = 400;
        }
        else
        {
            string userID = getUserIDFromToken(token, connectionString);
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"SELECT EXISTS(
                                        SELECT 1
                                        FROM tblConnections
                                        WHERE UserID = @UserID AND ChatID = @ChatID
                                    );";
                cmd.Parameters.AddWithValue("@UserID", userID);
                cmd.Parameters.AddWithValue("@ChatID", chatID);
                bool hasPermission = (Int64)cmd.ExecuteScalar() > 0;
                if (hasPermission)
                {
                    cmd.CommandText = @"SELECT IsDM
                                        FROM tbl ChatID
                                        WHERE ChatID = '{chatID}'";
                    bool isDM = (Int64)cmd.ExecuteScalar() > 0;
                    if (isDM)
                    {
                        messageText = messageText;
                    }
                    cmd.CommandText = @"INSERT INTO tblMessages (ChatID, TimeSent, MessageID, UserID, MessageText)
                                        VALUES (@ChatID, strftime('%s','now'), @MessageID, @UserID, @MessageText);";
                    cmd.Parameters.AddWithValue("@ChatID", chatID);
                    cmd.Parameters.AddWithValue("@MessageID", messageID);
                    cmd.Parameters.AddWithValue("@UserID", userID);
                    cmd.Parameters.AddWithValue("@MessageText", messageText);
                    cmd.ExecuteNonQuery();
                    responseMessage = null;
                    code = 200;
                }
                else
                {
                    var responseJson = new { error = "You do not have permission to post in this chat", errcode = "FORBIDDEN"};
                    responseMessage = JsonSerializer.Serialize(responseJson);
                    code = 403;
                }
            }
        }
        sendResponse(context, "application/json", code, responseMessage);
    }
    static void addUser(HttpListenerContext context, Uri uri, string connectionString)
    {
        //Checks if user exists before hashing the password and adding it to the database. Will respond with an error if the user allready exists.
        string responseMessage;
        int code;
        string? userName = context.Request.QueryString["userName"];
        string? password = context.Request.QueryString["password"];
        string? publicKey = context.Request.QueryString["publicKey"];
        if (string.IsNullOrEmpty(userName) | string.IsNullOrEmpty(publicKey) | string.IsNullOrEmpty(password))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonSerializer.Serialize(responseJson);
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
                cmd.Parameters.AddWithValue("@UserName", userName);
                bool userTaken = (Int64)cmd.ExecuteScalar() > 0;
                if (userTaken)
                {
                    var responseJson = new { error = "User with that name already exists", errcode = "NAME_IN_USE"};
                    responseMessage = JsonSerializer.Serialize(responseJson);
                    code = 400;
                }
                else
                {
                    string passHash = hash(password);
                    string userID = Guid.NewGuid().ToString();
                    cmd.CommandText = @"INSERT INTO tblUsers (UserID, UserName, PassHash)
                                        VALUES (@UserID, @UserName, @PassHash)";
                    cmd.Parameters.AddWithValue("@UserID", userID);
                    cmd.Parameters.AddWithValue("@UserName", userName);
                    cmd.Parameters.AddWithValue("@PassHash", passHash);
                    cmd.ExecuteNonQuery();
                    var responseJson = new { token = createToken(userID, connectionString) };
                    responseMessage = JsonSerializer.Serialize(responseJson);
                    code = 200;
                }  
            }
        }
        sendResponse(context, "application/json", code, responseMessage);
    }
    static void createChat(HttpListenerContext context, Uri uri, int isDM, string connectionString)
    {
        string responseMessage;
        int code;
        string? chatName = context.Request.QueryString["chatName"];
        string? token = context.Request.QueryString["token"];
        string? chatID = Guid.NewGuid().ToString();
        if (!tokenValid(token, connectionString))
        {
            var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
            responseMessage = JsonSerializer.Serialize(responseJson);
            code = 401;
        }
        else if (string.IsNullOrEmpty(chatName))
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonSerializer.Serialize(responseJson);
            code = 400;
        }
        else
        {
            string userID = getUserIDFromToken(token, connectionString);
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"INSERT INTO tblChats(ChatID, ChatName, IsDM)
                                    VALUES (@ChatID, @ChatName, @IsDM)";
                cmd.Parameters.AddWithValue("@ChatID", chatID);
                cmd.Parameters.AddWithValue("@ChatName", chatName);
                cmd.Parameters.AddWithValue("@IsDM", isDM);
                cmd.ExecuteNonQuery();
                cmd.CommandText = @"INSERT INTO tblConnections (UserID, ChatID, Admin)
                                    VALUES (@UserID, @ChatID, 1);";
                cmd.Parameters.AddWithValue("@UserID", userID);
                cmd.Parameters.AddWithValue("@ChatID", chatID);
                cmd.ExecuteNonQuery();
            }
            responseMessage = null;
            code = 200;
        }
        sendResponse(context, "application/json", code, responseMessage);
    }
    static string createToken(string userID, string connectionString)//generates a token that the client can then use to authenticate with
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
    static bool tokenValid(string token, string connectionString)
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
    static void login(HttpListenerContext context, Uri uri, string connectionString) //checks if the supplied username and password are correct, and returns a token if they are
    {

    }
}