using System;
using System.Reflection;
using uk.andyjohnson.Asiri.Core;

namespace uk.andyjohnson.Asiri.Core.Tests
{
    /// <summary>
    /// Verifies that no DiscUtils type is exposed by <see cref="DecryptedBlockDeviceStream"/>'s
    /// public API surface, by reflecting over its public constructors, methods, and properties. A
    /// manual code review can miss this if a member is added later; this test catches it
    /// automatically.
    /// </summary>
    public class DecryptedBlockDeviceStreamApiSurfaceTests
    {
        [Fact]
        public void PublicApiSurface_DoesNotReferenceDiscUtilsTypes()
        {
            var type = typeof(DecryptedBlockDeviceStream);
            var offendingMembers = new System.Collections.Generic.List<string>();

            foreach (var ctor in type.GetConstructors(BindingFlags.Public | BindingFlags.Instance))
            {
                foreach (var param in ctor.GetParameters())
                {
                    if (IsDiscUtilsType(param.ParameterType))
                    {
                        offendingMembers.Add($"constructor parameter '{param.Name}' : {param.ParameterType}");
                    }
                }
            }

            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                if (IsDiscUtilsType(method.ReturnType))
                {
                    offendingMembers.Add($"method '{method.Name}' return type : {method.ReturnType}");
                }
                foreach (var param in method.GetParameters())
                {
                    if (IsDiscUtilsType(param.ParameterType))
                    {
                        offendingMembers.Add($"method '{method.Name}' parameter '{param.Name}' : {param.ParameterType}");
                    }
                }
            }

            foreach (var prop in type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                if (IsDiscUtilsType(prop.PropertyType))
                {
                    offendingMembers.Add($"property '{prop.Name}' : {prop.PropertyType}");
                }
            }

            Assert.True(offendingMembers.Count == 0,
                "DiscUtils type(s) found in public API surface: " + string.Join(", ", offendingMembers));
        }

        private static bool IsDiscUtilsType(Type type)
        {
            return type.Namespace != null && type.Namespace.StartsWith("DiscUtils", StringComparison.Ordinal);
        }
    }
}
