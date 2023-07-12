using System;
using System.IO;
using System.Net;
using System.Web;
using System.Text;
///using System.Text.Json;
using Newtonsoft.Json;
using System.Text.Json.Serialization;
using System.Data.SQLite;
using System.Security.Cryptography;
class MessageServer
{
    static void Main(string[] args)
    {
        const string connectionString = "Data Source=data.db; Version=3; New=True; Compress=True;";
        createDB(connectionString);
        
        const string url = "http://localhost:8080/";//sets up http server
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
                case "/api/content/getMessages": apiGetMessages(context, uri, connectionString); break;
                case "/api/content/sendMessage": apiSendMessage(context, uri, connectionString); break;
                case "/api/directMessage/create": apiCreateChannel(context, uri, true, connectionString); break;
                case "/api/guild/createChannel": apiCreateChannel(context, uri, false, connectionString); break;
                case "/api/guild/create": apiCreateGuild(context, uri, connectionString); break;
                case "/api/guild/getDetails": apiGetGuildDetails(context, uri, connectionString); break;
                case "/api/guild/setDetails": apiSetGuildDetails(context, uri, connectionString); break;
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
                'ChanelDesc'    VARCHAR(100),
                'IsDM'          BOOL,
                'GuildID'       CHAR(36),
                PRIMARY KEY('ChannelID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblMessages' (
                'ChannelID'     CHAR(36),
                'TimeSent'      INT,
                'MessageID'     CHAR(36),
                'UserID'        CHAR(36),
                'MessageText'   VARCHAR(4000),
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
        Console.WriteLine("Sent response: " + responseMessage);
    }
    static string hash(string plaintext)
    {
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(plaintext)));
    }
    static void apiGetMessages(HttpListenerContext context, Uri uri, string connectionString)//Fetches message data from db if user has permission, and returns it as a json array.
    {
        List<string[]> messages = new List<string[]>();
        int code = 200;
        string responseMessage = "";
        string? channelID = context.Request.QueryString["channelID"];
        string? offset = context.Request.QueryString["offset"];
        string? token = context.Request.QueryString["token"];
        if (string.IsNullOrEmpty(channelID) | string.IsNullOrEmpty(token)) // If missing a perameter respond with an error
        {
            var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }

        //TODO: Add authentication.

        else
        {
            if (string.IsNullOrEmpty(offset)) offset = "0";
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"SELECT tblUsers.UserID, UserName, MessageID, TimeSent, MessageText
                                    FROM tblMessages, tblUsers, tblChannels
                                    WHERE tblChannels.ChannelID = @ChannelID
                                    AND tblMessages.UserID = tblUsers.UserID
                                    LIMIT 50 OFFSET @offset;";
                cmd.Parameters.AddWithValue("ChannelID", channelID);
                cmd.Parameters.AddWithValue("offset", offset);
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
            }
            responseMessage += "]"; 
            code = 200;
        }

        sendResponse(context, "application/json", code, responseMessage);
    }
    static void apiSendMessage(HttpListenerContext context, Uri uri, string connectionString)
    {
        string? channelID = context.Request.QueryString["channelID"];
        string? messageText = context.Request.QueryString["messageText"];
        string? token = context.Request.QueryString["token"];
        string messageID = Guid.NewGuid().ToString();
        int code;
        string? responseMessage;
        if (string.IsNullOrEmpty(channelID) | messageText is null | string.IsNullOrEmpty(token))
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
                cmd.CommandText = @"SELECT EXISTS(
                                        SELECT 1
                                        FROM tblGuildConnections, tblDMConnections
                                        WHERE tblGuildConnections.UserID = @UserID AND tblGuildConnections.ChannelID = @ChannelID
                                        OR tblDMConnections.UserID = @UserID AND tblDMConnections.ChannelID = @ChannelID
                                    );";
                cmd.Parameters.AddWithValue("UserID", userID);
                cmd.Parameters.AddWithValue("ChannelID", channelID);
                bool hasPermission = (Int64)cmd.ExecuteScalar() > 0; //Convert integer 1 or 0 into boolean
                if (hasPermission)
                {
                    cmd.CommandText = @"INSERT INTO tblMessages (ChannelID, TimeSent, MessageID, UserID, MessageText)
                                        VALUES (@ChannelID, strftime('%s','now'), @MessageID, @UserID, @MessageText);";
                    cmd.Parameters.AddWithValue("ChannelID", channelID);
                    cmd.Parameters.AddWithValue("MessageID", messageID);
                    cmd.Parameters.AddWithValue("UserID", userID);
                    cmd.Parameters.AddWithValue("MessageText", messageText);
                    cmd.ExecuteNonQuery();
                    responseMessage = null;
                    code = 200;
                }
                else
                {
                    var responseJson = new { error = "You do not have permission to post in this channel", errcode = "FORBIDDEN"};
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 403;
                }
            }
        }
        sendResponse(context, "application/json", code, responseMessage);
    }
    static void apiAddUser(HttpListenerContext context, Uri uri, string connectionString)
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
                    string passHash = hash(password);
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
        sendResponse(context, "application/json", code, responseMessage);
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
            sendResponse(context, "application/json", code, responseMessage);
        }
    }
    static void apiCreateChannel(HttpListenerContext context, Uri uri, bool isDM, string connectionString)
    {
        string? channelName = context.Request.QueryString["channelName"];
        string? token = context.Request.QueryString["token"];
        string? guildID = context.Request.QueryString["guildID"];
        string? userID2 = getUserIDFromUsername(context.Request.QueryString["userToAdd"], connectionString);
        string? responseMessage;
        int? channelType = int.Parse(context.Request.QueryString["channelType"]);
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
                createDM(userID1, userID2, connectionString);
                responseMessage = null;
                code = 200;
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
                    var responseJson = new { error = "Invalid GuildID", errcode = "INVALID_GUILDID" };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 400;
                }
            }
        }
        sendResponse(context, "application/json", code, responseMessage);
    }
    static void createDM(string userID1, string userID2, string connectionString)
    {
        string channelID = Guid.NewGuid().ToString();
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"INSERT INTO tblChannels(ChannelID, ChannelName, ChanelType, IsDM)
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
            }
            createChannel("General", guildID, 1, connectionString);
            var responseJson = new { GuildID = guildID};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 200;
        }
        sendResponse(context, "application/json", code, responseMessage);
    }
    static void apiGetGuildDetails(HttpListenerContext context, Uri uri, string connectionString) // Returns guild name, description and all users that are part of it.
    {

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
            responseMessage = null;
            code = 200;
        }
        sendResponse(context, "application/json", code, responseMessage);
    }
    static void apiCreateInvite(HttpListenerContext context, Uri uri, string connectionString)
    {
        Random rnd = new Random();
        string inviteCode = "";
        for (int i = 0; i < 8; i++)
        {
            inviteCode += ((char)(rnd.Next(1,26) + 64)).ToString();
        }
        // TODO: add invite to db and return it to user
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
        sendResponse(context, "application/json", code, responseMessage);
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