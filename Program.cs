using System.Net;
using System.Text;
using Newtonsoft.Json;
using System.Data.SQLite;
using System.Data;
using System.Security;
using System.Dynamic;
using System.Net.Mime;
using System.Windows.Markup;

class MessageServer
{
    // Global constants:
    const string typeJson = "application/json"; // For ease of use when sending a response.
    static readonly string logPath = @"logs\Server_" + DateTime.Now.ToString("yyyy-MM-dd_HH.mm.ss") + ".log"; // Cannot use a const because the time can't be calculated at compilation.
    const string connectionString = "Data Source=data.db; Version=3; New=True; Compress=True;";
    const bool logAllRequests = true;
    const int owner = 5;
    const int admin = 4;
    const int unprivileged = 3;    
    const int readWrite = 3;
    const int readOnly = 2;
    const int notInChannel = 1;
    const int notInGuild = 1;
    const int channelNotExist = 0;
    const int guildNotExist = 0;
    static void Main(string[] args)
    {
        using (var con = new SQLiteConnection(connectionString)) 
        {
            con.Open();
            log("DEBUG", "Using SQLite version: " + con.ServerVersion);
        }
        createDB(connectionString);
        const string url = "http://localhost:8080/"; // Sets up http server
        // TODO: log and give error if port is already in use.
        HttpListener listener = new HttpListener();
        listener.Prefixes.Add(url);
        listener.Start(); 
        Console.WriteLine("Listening for requests on " + url);
        log("INFO", "Started server at " + url);
        while (true)
        {
            HttpListenerContext context = listener.GetContext();
            Uri uri = new Uri(context.Request.Url.ToString());
            if (logAllRequests) {log("INFO", context.Request.UserHostAddress.ToString() + " accessed " + uri.AbsolutePath.ToString());}
            string responseMessage;
            try // This try catch should hopefully never run, but if needed it will stop the server from crashing.
            {
                switch (uri.AbsolutePath) // Calls function used for each api endpoint
                {
                    case "/api/content/getMessages": apiGetMessages(context); break; //Get
                    case "/api/content/sendMessage": apiSendMessage(context); break; //Post
                    case "/api/user/getInfo": apiGetUserInfo(context); break; //Get
                    case "/api/directMessage/create": apiCreateChannel(context, true); break; //Post
                    case "/api/guild/createChannel": apiCreateChannel(context, false); break; //Post
                    case "/api/guild/create": apiCreateGuild(context); break; //Post
                    case "/api/guild/listGuilds": apiListGuilds(context); break; //Get
                    case "/api/guild/fetchDetails": apiFetchGuildDetails(context); break; //Get
                    case "/api/guild/setDetails": apiSetGuildDetails(context); break; //Post
                    case "/api/guild/invite/create": apiCreateInvite(context); break; //Get
                    case "/api/guild/invite/list": apiListInvites(context); break; //Get
                    case "/api/guild/join": apiJoinGuildFromCode(context); break; //Post
                    case "/api/account/create": apiCreateUser(context); break; //Post
                    case "/api/account/login": apiLogin(context); break; //Post
                    case "/api/account/userID": apiReturnUserIDFromToken(context); break; //Get
                    case "/api/account/setPicture": apiSetPicture(context); break; //Post
                    case "/api/guild/key/request": apiRequestKeys(context); break; //Post
                    case "/api/guild/key/listRequests": apiGetKeyRequests(context); break; //Get
                    case "/api/guild/key/submit": apiSubmitKey(context); break; //Post
                    case "/api/guild/users/togglePerms": apiToggleUserPerms(context); break; //Post
                    case "/api/guild/users/list": apiListGuildUsers(context); break; //Get
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
                    }break;
                }
            }
            catch (Exception ex)
            {
                log("ERROR", ex.GetType() + "Error: \n", ex);
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
                'Type'          INTEGER,
                'MessageContent'   TEXT,
                'IV'            CHAR(32),
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
            );";
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
                'GuildKeyDigest' CHAR(32),
                PRIMARY KEY('GuildID'),
                FOREIGN KEY('OwnerID') REFERENCES 'tblUsers'('UserID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblKeyRequests' (
                'RequesterID'  CHAR(36),
                'GuildID'      CHAR(36),
                'EncryptedKey' TEXT,
                'ResponderID'  CHAR(36),
                FOREIGN KEY('RequesterID') REFERENCES 'tblUsers'('UserID'),
                FOREIGN KEY('GuildID') REFERENCES 'tblGuilds'('GuildID'),
                PRIMARY KEY('RequesterID', 'GuildID')
            );";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE IF NOT EXISTS 'tblInvites' (
                'Code'          CHAR(8),
                'GuildID'       CHAR(36),
                PRIMARY KEY('Code'),
                FOREIGN KEY('GuildID') REFERENCES 'tblGuilds'('GuildID')
            );";
            cmd.ExecuteNonQuery();
        }
    }
    static void sendResponse(HttpListenerContext context, string type, int code, string? responseMessage = null) // Sends data in response to a call from a client
    {
        try 
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
            if (logAllRequests)
            {
                Console.WriteLine("Sent response: " + responseMessage);
            }
        }
        catch(Exception ex) { log("ERROR", "Failed to send response", ex); }
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
                Console.WriteLine("[!ERROR] " + ex.GetType() + " exeption, see logs for details");
                File.AppendAllText(logPath, time + " [!ERROR]  " + desc + ex.ToString() + "\n\n");
            }break;
            case "WARNING":
            {
                Console.WriteLine("[WARNING] " + desc);
                File.AppendAllText(logPath, time + " [WARNING] " + desc + "\n\n");
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
    static dynamic parsePost(HttpListenerContext context)
    {
        string bodyContent;

        var request = context.Request;
        if (request.HttpMethod == "POST" && request.ContentType != null)
        {
            using (var body = request.InputStream)
            using (var reader = new StreamReader(body, request.ContentEncoding))
            {
                bodyContent = reader.ReadToEnd();
            }
        }
        else { bodyContent = null; }
        return bodyContent;
    }
    static dynamic parseJsonPost(HttpListenerContext context)
    {
        var request = context.Request;
        dynamic jsonBodyObject;
        if (request.HttpMethod == "POST" && request.ContentType != null && request.ContentType.Contains(typeJson))
        {
            var JsonBody = parsePost(context);
            jsonBodyObject = JsonConvert.DeserializeObject<dynamic>(JsonBody);
        }
        else { jsonBodyObject = null; }
        return jsonBodyObject;
    }
    static void returnInvalidTokenError(out string responseMessage, out int code)
    {
        var responseJson = new { error = "Invalid token", errcode = "INVALID_TOKEN" };
        responseMessage = JsonConvert.SerializeObject(responseJson);
        code = 401;
    }
    static void returnMissingParameterError(out string responseMessage, out int code)
    {
        var responseJson = new { error = "Missing a required parameter", errcode = "MISSING_PARAMETER"};
        responseMessage = JsonConvert.SerializeObject(responseJson);
        code = 400;
    }
    static void apiGetMessages(HttpListenerContext context) // Fetches message data from db if user has permission, and returns it as a json array.
    {
        List<Message> messages = new List<Message>();
        int code;
        string responseMessage;
        string? channelID = context.Request.QueryString["channelID"];
        string? afterMessageID = context.Request.QueryString["afterMessageID"];
        string? beforeMessageID = context.Request.QueryString["beforeMessageID"];
        string? token = context.Request.QueryString["token"];
        if (string.IsNullOrEmpty(channelID) | string.IsNullOrEmpty(token)) returnMissingParameterError(out responseMessage, out code);
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else
        {
            string userID = getUserIDFromToken(token);
            if (checkUserChannelPerms(channelID, userID) > notInChannel) // Has to have read permissions
            {
                using (var con = new SQLiteConnection(connectionString))
                using (var cmd = new SQLiteCommand(con))
                {
                    con.Open();
                    // Will return all messages in a channel if AfterMessageID is null, otherwise it will return only the messages after the message specified.
                    cmd.CommandText = @"SELECT * FROM
                                        (
                                            SELECT tblUsers.UserID, UserName, MessageID, TimeSent, MessageContent, IV, Type
                                            FROM tblMessages, tblUsers
                                            WHERE tblMessages.ChannelID = @ChannelID
                                            AND tblMessages.UserID = tblUsers.UserID
                                            AND (
                                                CASE 
                                                    WHEN @AfterMessageID IS NOT NULL AND tblMessages.TimeSent > (
                                                        SELECT TimeSent
                                                        FROM tblMessages
                                                        WHERE MessageID = @AfterMessageID
                                                    )
                                                    OR @BeforeMessageID IS NOT NULL AND tblMessages.TimeSent < (
                                                        SELECT TimeSent
                                                        FROM tblMessages
                                                        WHERE MessageID = @BeforeMessageID
                                                    )
                                                    OR (@AfterMessageID IS NULL AND @BeforeMessageID IS NULL)
                                                    THEN true
                                                    ELSE false
                                                END
                                            )
                                            ORDER BY TimeSent desc
                                            LIMIT 50
                                        )
                                        ORDER BY TimeSent ASC;"; 
                    cmd.Parameters.AddWithValue("AfterMessageID", afterMessageID);
                    cmd.Parameters.AddWithValue("BeforeMessageID", beforeMessageID);
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
                                Content = reader.GetString(4),
                                IV = reader.GetString(5),
                                Type = reader.GetInt32(6)
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
                sendResponse(context, typeJson, code, responseMessage);
                return;
            }
            responseMessage = JsonConvert.SerializeObject(messages);
            code = 200;
        }

        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiSendMessage(HttpListenerContext context)
    {
        Message message;
        string token;
        dynamic jsonBodyObject = parseJsonPost(context);
        int code;
        string? responseMessage;
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
        }
        if (string.IsNullOrEmpty((string)jsonBodyObject.channelID) | string.IsNullOrEmpty((string)jsonBodyObject.content) | string.IsNullOrEmpty(token)) //TODO: check for message type
            {returnMissingParameterError(out responseMessage, out code);}
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else
        {
            message = new Message
            {
                ID = Guid.NewGuid().ToString(),
                ChannelID = jsonBodyObject.channelID,
                Type = jsonBodyObject.type,
                Content = jsonBodyObject.content,
                IV = jsonBodyObject.iv,
            };
            message.UserID = getUserIDFromToken(token);
            if (checkUserChannelPerms(message.ChannelID, message.UserID) > readOnly) // Has to have higher privilages than read only
            {
                using (var con = new SQLiteConnection(connectionString))
                using (var cmd = new SQLiteCommand(con))
                {
                    con.Open();
                    cmd.CommandText = @"INSERT INTO tblMessages (ChannelID, TimeSent, MessageID, UserID, Type, MessageContent, IV)
                                        VALUES (@ChannelID, unixepoch('subsec'), @MessageID, @UserID, @Type, @MessageContent, @IV);";
                    cmd.Parameters.AddWithValue("ChannelID", message.ChannelID);
                    cmd.Parameters.AddWithValue("MessageID", message.ID);
                    cmd.Parameters.AddWithValue("UserID", message.UserID);
                    cmd.Parameters.AddWithValue("Type", message.Type);
                    cmd.Parameters.AddWithValue("MessageContent", message.Content);
                    cmd.Parameters.AddWithValue("IV", message.IV);
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
                    message.Time = (double)cmd.ExecuteScalar();

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
    private static void apiListGuildUsers(HttpListenerContext context)
    {
        string? token = context.Request.QueryString["token"];
        string? guildID = context.Request.QueryString["guildID"];
        string responseMessage;
        int code;
        if (string.IsNullOrEmpty(guildID) | string.IsNullOrEmpty(token)) returnMissingParameterError(out responseMessage, out code);
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else
        {
            string requesterUserID = getUserIDFromToken(token);
            if (checkUserGuildPerms(guildID, requesterUserID) > notInGuild) // Has to have read permissions
            {
                List<string> users = new List<string>{ };
                using (var con = new SQLiteConnection(connectionString))
                using (var cmd = new SQLiteCommand(con))
                {
                    con.Open();
                    cmd.CommandText = @"SELECT UserID
                                        FROM tblGuildConnections
                                        WHERE GuildID = @GuildID;";
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            users.Add(reader.GetString(0));
                        }
                    }
                }
                Dictionary<string, object> responseJson = new();
                foreach (string userID in users)
                {
                    int permissions = checkUserGuildPerms(guildID, userID);
                    User user = getUserInfoFromID(userID);
                    responseJson.Add(
                        userID,
                        new {
                             permissions = permissions,
                             userName = user.Name
                         }
                    );
                }
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 200;
            }
            else
            {
                var responseJson = new { error = "You do not have permission to read messages in this channel", errcode = "FORBIDDEN" };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 403;
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }    
    private static int checkUserGuildPerms(string guildID, string userID)
    {
        /* Returns:
            - 5 for Owner
            - 4 for Admin
            - 3 for unprivileged user
            - 1 for not in guild
            - 0 if guild does not exist
        */
        if (!checkGuildExists(guildID)) {return guildNotExist;}
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            // Check if ser is in guild
            cmd.CommandText = @"SELECT EXISTS(
                                    SELECT 1 
                                    FROM tblGuildConnections
                                    WHERE UserID = @UserID
                                    AND GuildID = @GuildID
                                );";
            cmd.Parameters.AddWithValue("UserID", userID);
            cmd.Parameters.AddWithValue("GuildID", guildID);
            bool inGuild = (Int64)cmd.ExecuteScalar() > 0;
            if (!inGuild) {return notInGuild;}

            // Check if user is the owner
            cmd.CommandText = @"SELECT OwnerID
                                FROM tblGuilds
                                WHERE GuildID = @GuildID;";
            cmd.Parameters.AddWithValue("GuildID", guildID);
            bool isOwner = (string)cmd.ExecuteScalar() == userID;
            if (isOwner) {return owner;}

            // Check if user has admin 
            cmd.CommandText = @"SELECT Admin
                                FROM tblGuildConnections
                                JOIN tblGuilds ON tblGuilds.GuildID = tblGuildConnections.GuildID
                                WHERE UserID = @UserID
                                AND tblGuilds.GuildID = @GuildID;";
            cmd.Parameters.AddWithValue("UserID", userID);
            cmd.Parameters.AddWithValue("GuildID", guildID);
            bool isAdmin = (bool)cmd.ExecuteScalar();
            if (isAdmin) {return admin;}

            // If the user is in the guild and is not the owner of an admin then the user has no extra permissions.
            return unprivileged; 
        }
    }
    private static int checkUserChannelPerms(string channelID, string userID) // Gets the permissions of the user. 0 is not in channel, 1 is a read only channel, 2 is a normal user, 3 is administrator, 4 is owner.
    {
        /* Returns:
            - 5 for Owner
            - 4 for Admin
            - 3 if user has read and message permission
            - 2 if read only (used for announcement or rule channels for example)
            - 1 if not in channel
            - 0 if channel does not exist
        */
        bool inDM;
        bool isDM;
        int guildPerms;
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"SELECT GuildID
                                FROM tblChannels
                                WHERE ChannelID = @ChannelID";
            cmd.Parameters.AddWithValue("ChannelID", channelID);
            var result = cmd.ExecuteScalar(); // Get the guildID to check the permissions
            if (result == null) // If the channel is in a DM, or doesn't exist
            {
                cmd.CommandText = @"SELECT IsDM
                                    FROM tblChannels
                                    WHERE ChannelID = @ChannelID;";
                cmd.Parameters.AddWithValue("ChannelID", channelID);
                isDM = (bool)cmd.ExecuteScalar();       
                if (!isDM) {return notInChannel;} // The channel does not exist
                cmd.CommandText = @"SELECT EXISTS(
                                        SELECT 1
                                        FROM tblDMConnections, tblChannels
                                        WHERE tblDMConnections.UserID = @UserID 
                                        AND tblDMConnections.ChannelID = @ChannelID
                                    );";  // Returns true if user is in the supplied Channel or DM
                cmd.Parameters.AddWithValue("UserID", userID);
                cmd.Parameters.AddWithValue("ChannelID", channelID);
                inDM = (Int64)cmd.ExecuteScalar() > 0; // Convert integer 1 or 0 into boolean
                if (inDM) {return readWrite;} // If in the DM the user will always have admin permissions.
                return channelNotExist; // If none of the other possibilities are true, the channel does not exist
            }
            else // If the channel is in a guild
            {
                string guildID = (string)result;
                guildPerms = checkUserGuildPerms(guildID, userID);
                if (guildPerms == unprivileged) // Normal user
                {
                    cmd.CommandText = @"SELECT ChannelType
                                        FROM tblChannels
                                        WHERE ChannelID = @ChannelID";
                    cmd.Parameters.AddWithValue("@ChannelID", channelID);
                    Int64 channelType = (Int64)cmd.ExecuteScalar();
                    return channelType == 1 ? readWrite : readOnly; // Return 2 if the channel is read only, 3 if read/write
                }
                else
                {
                    return guildPerms;
                }
            }
        }
    }
    static void apiGetUserInfo(HttpListenerContext context)
    {
        string? token = context.Request.QueryString["token"];
        string? requestedUserID = context.Request.QueryString["userID"];
        int code;
        string responseMessage;
        if (string.IsNullOrEmpty(token) | string.IsNullOrEmpty(requestedUserID)) returnMissingParameterError(out responseMessage, out code);
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code); 
        else
        {
            User user = getUserInfoFromID(requestedUserID);
            if (user == null)
            {
                var responseJson = new { error = "That UserID does not exist", errcode = "NOT_FOUND" };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 400;
            }
            else
            {
                responseMessage = JsonConvert.SerializeObject(user);
                code = 200;
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiCreateUser(HttpListenerContext context) // Checks if user exists before adding them to the database. Will respond with an error if the user allready exists.
    {
        string responseMessage;
        int code;
        string? userName;
        string? passHash;
        string? publicKey;
        dynamic jsonBodyObject = parseJsonPost(context);
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            userName = jsonBodyObject.userName;
            publicKey = jsonBodyObject.publicKey;
            passHash = jsonBodyObject.passHash;
        }
        if (string.IsNullOrEmpty(userName) | string.IsNullOrEmpty(publicKey) | string.IsNullOrEmpty(passHash)) {
            returnMissingParameterError(out responseMessage, out code); 
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
                    cmd.CommandText = @"INSERT INTO tblUsers (UserID, UserName, PassHash, PublicKey, Picture)
                                        VALUES (@UserID, @UserName, @PassHash, @PublicKey, '')";
                    cmd.Parameters.AddWithValue("UserID", userID);
                    cmd.Parameters.AddWithValue("UserName", userName);
                    cmd.Parameters.AddWithValue("PassHash", passHash);
                    cmd.Parameters.AddWithValue("PublicKey", publicKey);
                    cmd.ExecuteNonQuery();
                    var responseJson = new { token = createToken(userID) };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 200;
                }
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiSetPicture(HttpListenerContext context)
    {
        string responseMessage;
        int code;
        string? token;
        string? imageBase64;
        dynamic jsonBodyObject = parseJsonPost(context);
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
            imageBase64 = jsonBodyObject.image;
        }
        if (string.IsNullOrEmpty(imageBase64)) returnMissingParameterError(out responseMessage, out code);
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else
        {
            string userID = getUserIDFromToken(token);
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"UPDATE tblUsers
                                    SET Picture = @Picture
                                    WHERE UserID = @UserID";
                cmd.Parameters.AddWithValue("UserID", userID);
                cmd.Parameters.AddWithValue("Picture", imageBase64);
                cmd.ExecuteNonQuery();
                code = 200;
                responseMessage = null;
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiLogin(HttpListenerContext context) // Checks if the supplied username and password are correct, and returns a token if they are
    {
        string responseMessage;
        int code;
        string? userName;
        string? passHash;
        dynamic jsonBodyObject = parseJsonPost(context);
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            userName = jsonBodyObject.userName;
            passHash = jsonBodyObject.passHash;
        }
        if (string.IsNullOrEmpty(userName) | string.IsNullOrEmpty(passHash)) returnMissingParameterError(out responseMessage, out code);
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
                    var responseJson = new { token = createToken(userID) };
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
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiCreateChannel(HttpListenerContext context, bool isDM)
    {
        string? channelName;
        string? token;
        string? guildID;
        string? userID2;
        string? responseMessage;
        int? channelType;
        dynamic jsonBodyObject = parseJsonPost(context);
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
            channelName = jsonBodyObject.channelName;
            guildID = jsonBodyObject.guildID;
            userID2 = getUserIDFromUsername(jsonBodyObject.userToAdd);
        }
        if (!isDM)
        {
            channelType = int.Parse(jsonBodyObject.channelType);
        }
        else 
        {
            channelType = null;
        }
        int code;

        if (string.IsNullOrEmpty(channelName) | string.IsNullOrEmpty(token) | (isDM & string.IsNullOrEmpty(userID2)) | (!isDM & string.IsNullOrEmpty(guildID))) {
            returnMissingParameterError(out responseMessage, out code); 
        }
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else
        {
            string userID1 = getUserIDFromToken(token);
            if (isDM)
            {
                if (userID1 != userID2)
                {
                    createDM(userID1, userID2);
                    responseMessage = null;
                    code = 200;
                }
                else
                {
                    var responseJson = new { error = "You cannot add yourself to your own DM", errcode = "INVALID_DM" };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 400;
                }
            }
            else
            {
                
                int userPermission = checkUserGuildPerms(userID1, guildID);
                if (userPermission <= guildNotExist)
                {
                    var responseJson = new { error = "Invalid GuildID", errcode = "INVALID_GUILDID" };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 400;
                }
                else if (userPermission < admin) // Reject the request if the user has lower permissions than admin
                {
                    var responseJson = new { error = "You do not have permissions to carry out this action", errcode = "FORBIDDEN" };
                    responseMessage = JsonConvert.SerializeObject(responseJson);
                    code = 403;
                }
                else
                {
                    createChannel(channelName, guildID, (int)channelType);
                    responseMessage = null;
                    code = 200;
                }
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void createDM(string userID1, string userID2)
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
    static void createChannel(string channelName, string guildID, int channelType)
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
    static void apiCreateGuild(HttpListenerContext context)
    {
        string? guildKeyDigest;
        string guildID = Guid.NewGuid().ToString();
        string responseMessage;
        int code;
        string? token;
        string? guildName;
        string? guildDesc;
        dynamic jsonBodyObject = parseJsonPost(context);
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
            guildName = jsonBodyObject.guildName;
            guildKeyDigest = jsonBodyObject.guildKeyDigest;
        }
        if (string.IsNullOrEmpty(guildName) | string.IsNullOrEmpty(guildKeyDigest) | string.IsNullOrEmpty(token)) {
            returnMissingParameterError(out responseMessage, out code); 
        }
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else 
        {
            string userID = getUserIDFromToken(token);
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"INSERT INTO tblGuilds(GuildID, GuildName, OwnerID, GuildKeyDigest)
                                    VALUES (@GuildID, @GuildName, @OwnerID, @GuildKeyDigest);";
                cmd.Parameters.AddWithValue("GuildID", guildID);
                cmd.Parameters.AddWithValue("GuildName", guildName);
                cmd.Parameters.AddWithValue("OwnerID", userID);
                cmd.Parameters.AddWithValue("GuildKeyDigest", guildKeyDigest);
                cmd.ExecuteNonQuery();
            }
            addUserToGuild(userID, guildID, true);
            createChannel("General", guildID, 1);
            var responseJson = new { GuildID = guildID};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 200;
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void addUserToGuild(string userID, string guildID, bool isAdmin = false)
    {
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"INSERT INTO tblGuildConnections(UserID, GuildID, Admin)
                                VALUES (@UserID, @GuildID, @Admin);";
            cmd.Parameters.AddWithValue("UserID", userID);
            cmd.Parameters.AddWithValue("GuildID", guildID);
            cmd.Parameters.AddWithValue("Admin", isAdmin);
            cmd.ExecuteNonQuery();
        }
    }
    static void apiListGuilds(HttpListenerContext context) // Returns all guilds the user is part of, and the channels in each guild.
    {
        string? token = context.Request.QueryString["token"];
        string responseMessage;
        int code;
        if (string.IsNullOrEmpty(token)) returnMissingParameterError(out responseMessage, out code); 
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else 
        {
            List<dynamic> dbResponse = new List<dynamic>{};
            string userID = getUserIDFromToken(token);
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = 
                @"  SELECT tblGuilds.GuildID, GuildName, OwnerID, GuildDesc, GuildKeyDigest, ChannelID, ChannelName, ChannelType, ChannelDesc
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
                        string channelDesc = reader[8] == null ? null : reader[8].ToString(); // If description is null, set the variable to null to stop it from erroring.

                        var responseRow = new
                        {
                            GuildID = reader.GetString(0),
                            GuildName = reader.GetString(1),
                            GuildOwnerID = reader.GetString(2),
                            GuildDesc = guildDesc,
                            GuildKeyDigest = reader.GetString(4),
                            ChannelID = reader.GetString(5),
                            ChannelName = reader.GetString(6),
                            ChannelType = reader.GetInt32(7),
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
                    guildsJson += "\"guildName\": " + JsonConvert.SerializeObject(dbResponse[i].GuildName) + ", ";
                    guildsJson += "\"guildID\": \"" + dbResponse[i].GuildID + "\", ";
                    guildsJson += "\"guildOwnerID\": \"" + dbResponse[i].GuildOwnerID + "\", ";
                    guildsJson += "\"guildDesc\": " + JsonConvert.SerializeObject(dbResponse[i].GuildDesc) + ", ";
                    guildsJson += "\"guildKeyDigest\": \"" + dbResponse[i].GuildKeyDigest + "\", ";
                    guildsJson += "\"channels\": [";
                }
                guildsJson += "{"; // Build channel array in guilds json array.
                guildsJson += "\"channelName\": " + JsonConvert.SerializeObject(dbResponse[i].ChannelName) + ", ";
                guildsJson += "\"channelID\": \"" + dbResponse[i].ChannelID + "\", ";
                guildsJson += "\"channelDesc\": " + JsonConvert.SerializeObject(dbResponse[i].ChannelDesc) + ", ";
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
    static void apiFetchGuildDetails(HttpListenerContext context)
    {
        string? token = context.Request.QueryString["token"];
        string? guildID = context.Request.QueryString["guildID"];
        Guild guild = new();
        string responseMessage;
        int code = 500;
        if (string.IsNullOrEmpty(token) | string.IsNullOrEmpty(guildID)) returnMissingParameterError(out responseMessage, out code); 
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else 
        {
            string userID = getUserIDFromToken(token);
            if (checkUserGuildPerms(guildID, userID) < unprivileged) // Have to have admin permissions to create an invite 
            {
                var responseJson = new { error = "You are not in this guild", errcode = "FORBIDDEN" };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 403;
            }
            else
            {
                using (var con = new SQLiteConnection(connectionString)) 
                using (var cmd = new SQLiteCommand(con))
                {
                    con.Open();
                    cmd.CommandText = 
                    @"  SELECT GuildID, GuildName, OwnerID, GuildDesc, GuildKeyDigest
                        FROM tblGuilds
                        WHERE GuildID = @GuildID;";
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            string guildDesc = reader[3] == null ? null : reader[3].ToString();
                            guild = new Guild
                            {
                                ID = reader.GetString(0),
                                Name = reader.GetString(1),
                                OwnerID = reader.GetString(2),
                                Description = guildDesc,
                                KeyDigest = reader.GetString(4)
                            };
                            code = 200;
                        }
                    }
                }
            }
            responseMessage = JsonConvert.SerializeObject(guild);
            sendResponse(context, typeJson, code, responseMessage);
        }
    }
    static void apiSetGuildDetails(HttpListenerContext context)
    {
        string? token;
        string? guildID;
        string? guildName;
        string? guildDesc;
        dynamic jsonBodyObject = parseJsonPost(context);
        string responseMessage;
        int code;
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
            guildID = jsonBodyObject.guildID;
            guildName = jsonBodyObject.guildName;
            guildDesc = jsonBodyObject.guildDesc;
        }
        if (string.IsNullOrEmpty(guildID) | string.IsNullOrEmpty(token)) returnMissingParameterError(out responseMessage, out code); 
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else if (!checkGuildExists(guildID))
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
    static void apiCreateInvite(HttpListenerContext context)
    {
        string? guildID;
        string? token;
        dynamic jsonBodyObject = parseJsonPost(context);
        int code;
        string? responseMessage;
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
            guildID = jsonBodyObject.guildID;
        }
        if (string.IsNullOrEmpty(guildID) | string.IsNullOrEmpty(token)) returnMissingParameterError(out responseMessage, out code);
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else if (!checkGuildExists(guildID))
        {
            var responseJson = new { error = "Invalid GuildID", errcode = "INVALID_GUILDID" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else 
        {
            string userID = getUserIDFromToken(token);
            if (checkUserGuildPerms(guildID, userID) < admin) // Have to have admin permissions to create an invite 
            {
                var responseJson = new { error = "You do not have permission to create invites in this guild", errcode = "FORBIDDEN" };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 403;
            }
            else
            {
                Random rnd = new Random();
                string inviteCode = "";
                for (int i = 0; i < 8; i++)
                {
                    inviteCode += ((char)(rnd.Next(1,26) + 64)).ToString();
                }
                using (var con = new SQLiteConnection(connectionString)) 
                using (var cmd = new SQLiteCommand(con))
                {
                    con.Open();
                    bool collision = false;
                    do
                    {
                        cmd.CommandText = @"SELECT EXISTS(
                                                SELECT 1 
                                                FROM tblInvites
                                                WHERE Code = @Code
                                            )";
                        cmd.Parameters.AddWithValue("Code", inviteCode); 
                        collision = (Int64)cmd.ExecuteScalar() > 0;
                        if (collision == true)
                        {
                            log("WARNING", "Duplicate invite generated");
                        }          
                    } while (collision == true); // If an invite that allready exists is generated create a warning and regenerate it.

                    cmd.CommandText = @"INSERT INTO tblInvites (Code, GuildID)
                                        VALUES (@Code, @GuildID);";
                    cmd.Parameters.AddWithValue("Code", inviteCode);
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    cmd.ExecuteNonQuery();
                }
                var responseJson = new { code = inviteCode };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 200;
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiListInvites(HttpListenerContext context)
    {
        string? guildID = context.Request.QueryString["guildID"];
        string? token = context.Request.QueryString["token"];
        string responseMessage;
        List<string> inviteCodes = new List<string>();
        int code;

        if (string.IsNullOrEmpty(guildID) | string.IsNullOrEmpty(token)) returnMissingParameterError(out responseMessage, out code); 
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else if (!checkGuildExists(guildID))
        {
            var responseJson = new { error = "Invalid GuildID", errcode = "INVALID_GUILDID" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else 
        {
            string userID = getUserIDFromToken(token);
            if (checkUserGuildPerms(guildID, userID) < admin) // Have to have admin permissions to create an invite 
            {
                var responseJson = new { error = "You do not have permission to fetch invites for this guild", errcode = "FORBIDDEN" };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 403;
            }
            else
            {
                using (var con = new SQLiteConnection(connectionString)) 
                using (var cmd = new SQLiteCommand(con))
                {
                    con.Open();
                    cmd.CommandText = @"SELECT Code
                                        FROM tblInvites
                                        WHERE GuildID = @GuildID;";
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    using (SQLiteDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read()) // Loops through each code and adds it to the code list
                        {
                            inviteCodes.Add(reader.GetString(0));
                        }
                    }
                }
                var responseJson = new { inviteCodes };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 200;
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiJoinGuildFromCode(HttpListenerContext context)
    {
        string? inviteCode;
        string? token;
        dynamic jsonBodyObject = parseJsonPost(context);
        int code;
        string? responseMessage;
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
            inviteCode = jsonBodyObject.code;
        }

        if (string.IsNullOrEmpty(inviteCode) | string.IsNullOrEmpty(token)) returnMissingParameterError(out responseMessage, out code); 
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else 
        {
            object result;
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = @"SELECT GuildID
                                    FROM tblInvites
                                    WHERE Code = @Code;";
                cmd.Parameters.AddWithValue("Code", inviteCode);
                result = cmd.ExecuteScalar();
            }    
            if (result != null)
            {
                string guildID = (string)result;
                string userID = getUserIDFromToken(token);
                addUserToGuild(userID, guildID);
                var responseJson = new { guildID = guildID };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 200;
            }
            else 
            {
                var responseJson = new { error = "Invalid invite code", errcode = "INVALID_INVITE"};
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 400;
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiToggleUserPerms(HttpListenerContext context) // Sets a users permissions to be admin if they are a normal user and vice versa
    {
        string? token;
        string? guildID;
        string? targetUserID;
        dynamic jsonBodyObject = parseJsonPost(context);
        int code;
        string? responseMessage;
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
            guildID = jsonBodyObject.guildID;
            targetUserID = jsonBodyObject.userID;
        }
        if (string.IsNullOrEmpty(token) | string.IsNullOrEmpty(guildID) | string.IsNullOrEmpty(targetUserID)) returnMissingParameterError(out responseMessage, out code);
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else if (!checkGuildExists(guildID))
        {
            var responseJson = new { error = "Invalid GuildID", errcode = "INVALID_GUILDID" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else
        {
            string userID = getUserIDFromToken(token);
            if (checkUserGuildPerms(guildID, userID) < admin)
            {
                var responseJson = new { error = "You do not have permission to change user permissions in this guild", errcode = "FORBIDDEN" };
                responseMessage = JsonConvert.SerializeObject(responseJson);
                code = 403;
            }
            else
            {
                using (var con = new SQLiteConnection(connectionString))
                using (var cmd = new SQLiteCommand(con))
                {
                    con.Open();
                    cmd.CommandText = @"UPDATE tblGuildConnections
                                        SET Admin = 1 - Admin
                                        WHERE GuildID = @GuildID AND UserID = @UserID";
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    cmd.Parameters.AddWithValue("UserID", userID);
                    cmd.ExecuteNonQuery();
                }
                responseMessage = null;
                code = 200;
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiRequestKeys(HttpListenerContext context)
    {
        string? token;
        string? guildID;
        dynamic jsonBodyObject = parseJsonPost(context);
        int code;
        string? responseMessage;
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
            guildID = jsonBodyObject.guildID;
        }
        if (string.IsNullOrEmpty(token) | string.IsNullOrEmpty(guildID)) returnMissingParameterError(out responseMessage, out code);
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else if (!checkGuildExists(guildID))
        {
            var responseJson = new { error = "Invalid GuildID", errcode = "INVALID_GUILDID" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else
        {
            string userID = getUserIDFromToken(token);
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open();
                cmd.CommandText = 
                    @"SELECT EXISTS( 
                        SELECT 1
                        FROM tblKeyRequests
                        WHERE RequesterID = @UserID 
                        AND GuildID = @GuildID
                    );"; // Checks if the user has allready submited a request for the key for that guild before.
                cmd.Parameters.AddWithValue("UserID", userID);
                cmd.Parameters.AddWithValue("GuildID", guildID);
                bool alreadyRequested = (Int64)cmd.ExecuteScalar() > 0;
                if (alreadyRequested)
                {
                    cmd.CommandText = 
                        @"SELECT EncryptedKey, ResponderID
                        FROM tblKeyRequests
                        WHERE RequesterID = @UserID 
                        AND GuildID = @GuildID
                        AND EncryptedKey IS NOT NULL;";
                    cmd.Parameters.AddWithValue("UserID", userID);
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    bool keysReturned;
                    using (SQLiteDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            var keys = new {
                                key = reader.GetString(0),
                                userID = reader.GetString(1),
                            };
                            responseMessage = JsonConvert.SerializeObject(keys);
                            code = 200;
                            keysReturned = true;
                        } 
                        else // If no other users have responded the the request will return nothing
                        {
                            responseMessage = null;
                            code = 202; 
                            keysReturned = false;
                        }
                    }
                    if (keysReturned)
                    {
                        // After successfully returning the key, delete the request from the db
                        // so if the user needs to request it again there are no problems.
                        cmd.CommandText = @"DELETE FROM tblKeyRequests
                                            WHERE RequesterID = @UserID
                                            AND GuildID = @GuildID;";
                        cmd.Parameters.AddWithValue("UserID", userID);
                        cmd.Parameters.AddWithValue("GuildID", guildID);
                        cmd.ExecuteNonQuery();
                    }
                }
                else // If the client has not previously requested details for that guild, store the request.
                {
                    cmd.CommandText = @"INSERT INTO tblKeyRequests(RequesterID, GuildID)
                                        VALUES (@UserID, @GuildID);";
                    cmd.Parameters.AddWithValue("UserID", userID);
                    cmd.Parameters.AddWithValue("GuildID", guildID);
                    cmd.ExecuteNonQuery();
                    code = 200;
                    responseMessage = null;
                }
            }
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static void apiGetKeyRequests(HttpListenerContext context)
    {
        string? token = context.Request.QueryString["token"];
        string responseMessage;
        int code;
        if (string.IsNullOrEmpty(token)) returnMissingParameterError(out responseMessage, out code);
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else
        {
            string userID = getUserIDFromToken(token);
            object[] keyRequests = checkKeyRequests(userID);
            // Convert the keyRequests object array into json
            // responseMessage = "[{ \"keyRequests\": [";
            // for (int i=0; i < keyRequests.Length; i++)
            // {
            //     dynamic request = keyRequests[i];
            //     responseMessage += "{";
            //     responseMessage += "\"userID\": \"" + (string)request.UserID + "\", ";
            //     responseMessage += "\"guildID\": \"" + (string)request.GuildID + "\"";
            //     responseMessage += "}";
            //     if (i + 1 != keyRequests.Length)
            //     {
            //         responseMessage += ", ";
            //     }
            // }
            // responseMessage += "]}]";
            responseMessage = JsonConvert.SerializeObject(keyRequests);
            code = 200;
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static object[] checkKeyRequests(string userID)
    {
        List<object> keyRequests = new();
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open(); 
            cmd.CommandText = 
                @"SELECT tblKeyRequests.GuildID, RequesterID
                FROM tblKeyRequests, tblGuildConnections
                WHERE tblGuildConnections.GuildID = tblKeyRequests.GuildID
                AND tblGuildConnections.UserID = @UserID
                AND ResponderID IS NULL;"; 
            cmd.Parameters.AddWithValue("UserID", userID);
            
            using (SQLiteDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read()) // Loops through each message and adds it to the message list
                {
                    var responseRow = new
                    {
                        GuildID = reader.GetString(0),
                        UserID = reader.GetString(1),
                    };
                    keyRequests.Add(responseRow);
                }
            }
        }
        return keyRequests.ToArray();
    }
    static void apiSubmitKey(HttpListenerContext context)
    {
        string? token;
        string? guildID;
        string? keyCypherText;
        string? requesterID;
        dynamic jsonBodyObject = parseJsonPost(context);
        int code;
        string? responseMessage;
        if (jsonBodyObject == null)
        {
            var responseJson = new { error = "Incorrectly formatted request", errcode = "FORMATTING_ERROR"};
            responseMessage = JsonConvert.SerializeObject(responseJson);
            sendResponse(context, typeJson, 400, responseMessage);
            return;
        }
        else
        {
            token = jsonBodyObject.token;
            guildID = jsonBodyObject.guildID;
            requesterID = jsonBodyObject.userID;
            keyCypherText = jsonBodyObject.keyCypherText;
        }
        if (string.IsNullOrEmpty(token) | string.IsNullOrEmpty(guildID) | string.IsNullOrEmpty(requesterID) | string.IsNullOrEmpty(keyCypherText))
            { returnMissingParameterError(out responseMessage, out code); }
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else if (!checkGuildExists(guildID))
        {
            var responseJson = new { error = "Invalid GuildID", errcode = "INVALID_GUILDID" };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 400;
        }
        else
        {
            string userID = getUserIDFromToken(token);
            using (var con = new SQLiteConnection(connectionString))
            using (var cmd = new SQLiteCommand(con))
            {
                con.Open(); 
                cmd.CommandText = 
                    @"UPDATE tblKeyRequests
                    SET ResponderID = @ResponderID, EncryptedKey = @Key
                    WHERE RequesterID = @RequesterID
                    AND GuildID = @GuildID;";
                cmd.Parameters.AddWithValue("ResponderID", userID);
                cmd.Parameters.AddWithValue("Key", keyCypherText);
                cmd.Parameters.AddWithValue("RequesterID", requesterID);
                cmd.Parameters.AddWithValue("GuildID", guildID);
                cmd.ExecuteNonQuery();
            }
            responseMessage = null;
            code = 200;
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static string[] getPings(string userID)
    {
        // TODO: Fetch ping message id's and return them as an array
        string[] pingMessageIDs = {};
        return pingMessageIDs;
    }
    static string createToken(string userID)// Generates a token that the client can then use to authenticate with
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
    static string getUserIDFromToken(string token)
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
            userID = (string)cmd.ExecuteScalar();
        }
        return userID;
    }
    static bool tokenValid(string? token)
    {
        bool valid;
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"SELECT EXISTS(
                                    SELECT 1 
                                    FROM tblTokens
                                    WHERE Token = @Token
                                );";
            cmd.Parameters.AddWithValue("Token", token);
            valid = (Int64)cmd.ExecuteScalar() > 0;
        }
        return valid;
    }
    static void apiReturnUserIDFromToken(HttpListenerContext context) // Returns the UserID to the user when given a token.
    {
        string? token = context.Request.QueryString["token"];
        string userID;
        string responseMessage;
        int code;
        if (string.IsNullOrEmpty(token)) returnMissingParameterError(out responseMessage, out code);
        else if (!tokenValid(token)) returnInvalidTokenError(out responseMessage, out code);
        else
        {
            userID = getUserIDFromToken(token);
            var responseJson = new { userID = userID };
            responseMessage = JsonConvert.SerializeObject(responseJson);
            code = 200;
        }
        sendResponse(context, typeJson, code, responseMessage);
    }
    static string getUserIDFromUsername(string? userName)// Looks up a UserName and returns the asociated UserID
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
    static User getUserInfoFromID(string userID)
    {
        User user = new User();
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"SELECT UserID, UserName, Picture, Description, PublicKey
                                FROM tblUsers
                                WHERE UserID = @UserID";
            cmd.Parameters.AddWithValue("UserID", userID);
            using (SQLiteDataReader reader = cmd.ExecuteReader())
            {
                if (reader.Read())
                {
                    string description = reader[3] == null ? null : reader[3].ToString();
                    user = new User
                    {
                        ID = reader.GetString(0),
                        Name = reader.GetString(1),
                        Picture = reader.GetString(2),
                        Description = description,
                        PublicKey = reader.GetString(4),
                    };
                }
            }
        }
        return user;
    }
    static bool checkGuildExists(string guildID)
    {
        bool guildExists;
        using (var con = new SQLiteConnection(connectionString))
        using (var cmd = new SQLiteCommand(con))
        {
            con.Open();
            cmd.CommandText = @"SELECT EXISTS(
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