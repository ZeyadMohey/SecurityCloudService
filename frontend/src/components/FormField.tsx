/*FormField (used by Login and Register)*/

interface Props {
  id: string;
  label: string;
  error?: string;
  children: React.ReactNode;
}

export default function FormField({ id, label, error, children }: Props) {
  return (
    <div>
      <label
        htmlFor={id}
        className="block text-sm font-medium text-gray-400 mb-1.5"
      >
        {label}
      </label>
      {children}
      {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
    </div>
  );
}
