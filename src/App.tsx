import { useState, useEffect, type FormEvent } from 'react';
import DOMPurify from 'dompurify';

// Interfaces
interface Secret {
  id: number;
  content: string;
}

// Declaración global para Bootstrap
declare global {
  interface Window {
    bootstrap: any;
  }
}

function App() {
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [editingId, setEditingId] = useState<number | null>(null);
  const [modalInstance, setModalInstance] = useState<any>(null);
  const [errorMsg, setErrorMsg] = useState('');

  // Detectar entorno para la URL de la API
  const API_URL = window.location.hostname === 'localhost' 
    ? 'http://localhost:3001/api/secrets' 
    : '/api/secrets';

  // --- FUNCIONES DE SEGURIDAD ---
  
  // Sanitización en cliente (primera barrera)
  const sanitize = (dirty: string) => DOMPurify.sanitize(dirty);

  // Cargar datos
  const fetchSecrets = async () => {
    try {
      const res = await fetch(API_URL);
      if (!res.ok) throw new Error('Error de red');
      const data = await res.json();
      setSecrets(data);
    } catch (error) {
      console.error("Error seguro: Detalles ocultos al usuario.");
    }
  };

  useEffect(() => {
    fetchSecrets();
    // Inicializar modal de Bootstrap
    const modalEl = document.getElementById('editModal');
    if (modalEl && window.bootstrap) {
      const modal = new window.bootstrap.Modal(modalEl);
      setModalInstance(modal);
    }
  }, []);

  // Manejar Create
  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    
    // Validación Frontend
    const cleanInput = sanitize(inputValue);
    if (!cleanInput.trim()) return;

    try {
      const res = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: cleanInput }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Error desconocido');
      }

      setInputValue('');
      fetchSecrets();
    } catch (err: any) {
      setErrorMsg(err.message);
    }
  };

  // Manejar Update
  const handleUpdate = async () => {
    if (editingId === null) return;
    setErrorMsg('');

    const cleanInput = sanitize(inputValue);

    try {
      const res = await fetch(`${API_URL}/${editingId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: cleanInput }),
      });

      if (!res.ok) throw new Error('No se pudo actualizar');

      fetchSecrets();
      setInputValue('');
      setEditingId(null);
      modalInstance?.hide();
    } catch (err) {
      setErrorMsg("Error al actualizar. Verifique que no use caracteres especiales prohibidos.");
    }
  };

  // Preparar Modal para Editar
  const openEditModal = (secret: Secret) => {
    setEditingId(secret.id);
    setInputValue(secret.content); // Cargar dato existente
    setErrorMsg('');
    modalInstance?.show();
  };

  // Manejar Delete
  const handleDelete = async (id: number) => {
    if (!confirm('¿Está seguro de eliminar este registro?')) return;
    
    try {
      await fetch(`${API_URL}/${id}`, { method: 'DELETE' });
      fetchSecrets();
    } catch (err) {
      console.error("Error al eliminar");
    }
  };

  return (
    <div className="container mt-5" style={{ maxWidth: '800px' }}>
      <div className="card shadow-sm border-0">
        <div className="card-header bg-dark text-white text-center py-3">
          <h3 className="mb-0"> CRUD SEGURO</h3>
          <small className="text-white-50"> SEGURIDAD </small>
        </div>
        
        <div className="card-body p-4">
          {/* FORMULARIO DE CREACIÓN */}
          <form onSubmit={handleCreate} className="mb-5">
            <div className="input-group input-group-lg">
              <input
                type="text"
                className="form-control"
                placeholder="Escribe algo..."
                value={editingId === null ? inputValue : ''} 
                onChange={(e) => editingId === null && setInputValue(e.target.value)}
                maxLength={100} // Límite duro en cliente
                required
              />
              <button className="btn btn-primary px-4 fw-bold" type="submit">
                GUARDAR
              </button>
            </div>
            <div className="form-text text-muted mt-2">
              <i className="bi bi-shield-check"></i> Solo se permiten caracteres alfanuméricos. HTML y scripts serán bloqueados.
            </div>
            {errorMsg && editingId === null && (
              <div className="alert alert-danger mt-2 py-2">{errorMsg}</div>
            )}
          </form>

          <hr className="my-4" />

          {/* LISTA DE DATOS */}
          <h5 className="mb-3 text-secondary">Registros Guardados</h5>
          {secrets.length === 0 ? (
            <div className="text-center text-muted fst-italic py-4">
              No hay secretos guardados aún...
            </div>
          ) : (
            <div className="list-group">
              {secrets.map((secret) => (
                <div key={secret.id} className="list-group-item d-flex justify-content-between align-items-center">
                  <span className="fw-medium text-break pe-3">
                    {/* Renderizado Seguro */}
                    {secret.content}
                  </span>
                  <div className="btn-group">
                    <button 
                      className="btn btn-outline-secondary btn-sm"
                      onClick={() => openEditModal(secret)}
                    >
                      Editar
                    </button>
                    <button 
                      className="btn btn-outline-danger btn-sm"
                      onClick={() => handleDelete(secret.id)}
                    >
                      Eliminar
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* MODAL DE EDICIÓN (Bootstrap) */}
      <div className="modal fade" id="editModal" tabIndex={-1} aria-hidden="true">
        <div className="modal-dialog">
          <div className="modal-content">
            <div className="modal-header bg-light">
              <h5 className="modal-title">Editar Registro</h5>
              <button type="button" className="btn-close" onClick={() => modalInstance?.hide()}></button>
            </div>
            <div className="modal-body">
              <input
                type="text"
                className="form-control form-control-lg"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
              />
              {errorMsg && editingId !== null && (
                <div className="alert alert-danger mt-2">{errorMsg}</div>
              )}
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={() => modalInstance?.hide()}>Cancelar</button>
              <button type="button" className="btn btn-success" onClick={handleUpdate}>Guardar Cambios</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;