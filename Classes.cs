using System;
using System.Text;
using Newtonsoft.Json;
class Message
{
    public string MessageID {get; set;}
    public string UserID {get; set;}
    public string UserName {get; set;}
    public string TimeSent {get; set;}
    public string MessageText {get; set;}
}
class Guild
{
    public string Name;
    public string ID;
    public string OwnerID;
    public string Description;
    public List<Channel> Channels;
}
class Channel
{
    public string Name;
    public string ID;
    public int Type;
    public string Description;
    public int IsDM;
}
