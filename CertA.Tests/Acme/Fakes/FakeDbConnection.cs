using System.Data;

namespace CertA.Tests.Acme.Fakes;

/// <summary>
/// Fake IDbConnection that returns a single row with Id=1 for any command (for Dapper RETURNING ""Id"" in tests).
/// </summary>
public sealed class FakeDbConnection : IDbConnection
{
    private ConnectionState _state;

    public string ConnectionString { get; set; } = ""!;
    public int ConnectionTimeout => 0;
    public string Database => "";
    public ConnectionState State => _state;

    public IDbTransaction BeginTransaction() => throw new NotSupportedException();
    public IDbTransaction BeginTransaction(IsolationLevel il) => throw new NotSupportedException();
    public void ChangeDatabase(string databaseName) { }
    public void Close() => _state = ConnectionState.Closed;
    public IDbCommand CreateCommand() => new FakeDbCommand();
    public void Open() => _state = ConnectionState.Open;
    public void Dispose() => Close();
}

public sealed class FakeDbCommand : IDbCommand
{
    public string CommandText { get; set; } = ""!;
    public int CommandTimeout { get; set; }
    public CommandType CommandType { get; set; }
    public IDbConnection? Connection { get; set; }
    public IDataParameterCollection Parameters => new FakeParameterCollection();
    public IDbTransaction? Transaction { get; set; }
    public UpdateRowSource UpdatedRowSource { get; set; }

    public void Cancel() { }
    public IDbDataParameter CreateParameter() => new FakeDbParameter();
    public void Prepare() { }
    public void Dispose() { }

    public int ExecuteNonQuery() => 1;

    public IDataReader ExecuteReader() => new FakeDataReader(1);
    public IDataReader ExecuteReader(CommandBehavior behavior) => new FakeDataReader(1);

    public object? ExecuteScalar()
    {
        return 1;
    }
}

public sealed class FakeDataReader : IDataReader
{
    private readonly int _returnId;
    private bool _readOnce;

    public FakeDataReader(int returnId) { _returnId = returnId; }

    public int Depth => 0;
    public bool IsClosed => false;
    public int RecordsAffected => 1;
    public int FieldCount => 1;

    public void Close() { }
    public void Dispose() { }
    public bool GetBoolean(int i) => throw new NotSupportedException();
    public byte GetByte(int i) => throw new NotSupportedException();
    public long GetBytes(int i, long fieldOffset, byte[]? buffer, int bufferoffset, int length) => 0;
    public char GetChar(int i) => throw new NotSupportedException();
    public long GetChars(int i, long fieldoffset, char[]? buffer, int bufferoffset, int length) => 0;
    public IDataReader GetData(int i) => throw new NotSupportedException();
    public string GetDataTypeName(int i) => "integer";
    public DateTime GetDateTime(int i) => default;
    public decimal GetDecimal(int i) => default;
    public double GetDouble(int i) => default;
    public Type GetFieldType(int i) => typeof(int);
    public float GetFloat(int i) => default;
    public Guid GetGuid(int i) => default;
    public short GetInt16(int i) => default;
    public int GetInt32(int i) => _returnId;
    public long GetInt64(int i) => _returnId;
    public string GetName(int i) => "Id";
    public int GetOrdinal(string name) => 0;
    public DataTable? GetSchemaTable() => null;
    public string GetString(int i) => _returnId.ToString();
    public object GetValue(int i) => _returnId;
    public object this[int i] => _returnId;
    public object this[string name] => _returnId;
    public int GetValues(object[] values)
    {
        if (values != null && values.Length > 0) values[0] = _returnId;
        return 1;
    }
    public bool IsDBNull(int i) => false;
    public bool NextResult() => false;
    public bool Read()
    {
        if (_readOnce) return false;
        _readOnce = true;
        return true;
    }
}

public sealed class FakeDbParameter : IDbDataParameter
{
    public byte Precision { get; set; }
    public byte Scale { get; set; }
    public int Size { get; set; }
    public DbType DbType { get; set; }
    public ParameterDirection Direction { get; set; }
    public bool IsNullable { get; set; }
    public string ParameterName { get; set; } = "";
    public string SourceColumn { get; set; } = "";
    public DataRowVersion SourceVersion { get; set; }
    public object? Value { get; set; }
}

public sealed class FakeParameterCollection : IDataParameterCollection
{
    public object? this[string parameterName] { get => null; set { } }
    public object? this[int index] { get => null; set { } }
    public int Count => 0;
    public bool IsFixedSize => true;
    public bool IsReadOnly => false;
    public bool IsSynchronized => false;
    public object SyncRoot => this;
    public int Add(object? value) => 0;
    public void Clear() { }
    public bool Contains(string parameterName) => false;
    public bool Contains(object? value) => false;
    public void CopyTo(Array array, int index) { }
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => Array.Empty<object>().GetEnumerator();
    public int IndexOf(string parameterName) => -1;
    public int IndexOf(object? value) => -1;
    public void Insert(int index, object? value) { }
    public void Remove(object? value) { }
    public void RemoveAt(string parameterName) { }
    public void RemoveAt(int index) { }
}
